// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

// parse hex string into a []byte.
func parseHex(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, "0x") {
		return nil, errors.New("not a hex number")
	}
	return hex.DecodeString(tok[2:])
}

// parseWitnessStack parses a json array of witness items encoded as hex into a
// slice of witness elements.
func parseWitnessStack(elements []interface{}) ([][]byte, error) {
	witness := make([][]byte, len(elements))
	for i, e := range elements {
		witElement, err := hex.DecodeString(e.(string))
		if err != nil {
			return nil, err
		}

		witness[i] = witElement
	}

	return witness, nil
}

// shortFormOps holds a map of opcode names to values for use in short form
// parsing.  It is declared here so it only needs to be created once.
var shortFormOps map[string]byte

// parseShortForm parses a string as as used in the Bitcoin Core reference tests
// into the script it came from.
//
// The format used for these tests is pretty simple if ad-hoc:
//   - Opcodes other than the push opcodes and unknown are present as
//     either OP_NAME or just NAME
//   - Plain numbers are made into push operations
//   - Numbers beginning with 0x are inserted into the []byte as-is (so
//     0x14 is OP_DATA_20)
//   - Single quoted strings are pushed as data
//   - Anything else is an error
func parseShortForm(script string) ([]byte, error) {
	// Only create the short form opcode map once.
	if shortFormOps == nil {
		ops := make(map[string]byte)
		for opcodeName, opcodeValue := range OpcodeByName {
			if strings.Contains(opcodeName, "OP_UNKNOWN") {
				continue
			}
			ops[opcodeName] = opcodeValue

			// The opcodes named OP_# can't have the OP_ prefix
			// stripped or they would conflict with the plain
			// numbers.  Also, since OP_FALSE and OP_TRUE are
			// aliases for the OP_0, and OP_1, respectively, they
			// have the same value, so detect those by name and
			// allow them.
			if (opcodeName == "OP_FALSE" || opcodeName == "OP_TRUE") ||
				(opcodeValue != OP_0 && (opcodeValue < OP_1 ||
					opcodeValue > OP_16)) {

				ops[strings.TrimPrefix(opcodeName, "OP_")] = opcodeValue
			}
		}
		shortFormOps = ops
	}

	// Split only does one separator so convert all \n and tab into  space.
	script = strings.Replace(script, "\n", " ", -1)
	script = strings.Replace(script, "\t", " ", -1)
	tokens := strings.Split(script, " ")
	builder := NewScriptBuilder()

	for _, tok := range tokens {
		if len(tok) == 0 {
			continue
		}
		// if parses as a plain number
		if num, err := strconv.ParseInt(tok, 10, 64); err == nil {
			builder.AddInt64(num)
			continue
		} else if bts, err := parseHex(tok); err == nil {
			// Concatenate the bytes manually since the test code
			// intentionally creates scripts that are too large and
			// would cause the builder to error otherwise.
			if builder.err == nil {
				builder.script = append(builder.script, bts...)
			}
		} else if len(tok) >= 2 &&
			tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			builder.AddFullData([]byte(tok[1 : len(tok)-1]))
		} else if opcode, ok := shortFormOps[tok]; ok {
			builder.AddOp(opcode)
		} else {
			return nil, fmt.Errorf("bad token %q", tok)
		}

	}
	return builder.Script()
}

// parseScriptFlags parses the provided flags string from the format used in the
// reference tests into ScriptFlags suitable for use in the script engine.
func parseScriptFlags(flagStr string) (ScriptFlags, error) {
	var flags ScriptFlags

	sFlags := strings.Split(flagStr, ",")
	for _, flag := range sFlags {
		switch flag {
		case "":
			// Nothing.
		case "CHECKLOCKTIMEVERIFY":
			flags |= ScriptVerifyCheckLockTimeVerify
		case "CHECKSEQUENCEVERIFY":
			flags |= ScriptVerifyCheckSequenceVerify
		case "CLEANSTACK":
			flags |= ScriptVerifyCleanStack
		case "DERSIG":
			flags |= ScriptVerifyDERSignatures
		case "DISCOURAGE_UPGRADABLE_NOPS":
			flags |= ScriptDiscourageUpgradableNops
		case "LOW_S":
			flags |= ScriptVerifyLowS
		case "MINIMALDATA":
			flags |= ScriptVerifyMinimalData
		case "NONE":
			// Nothing.
		case "NULLDUMMY":
			flags |= ScriptStrictMultiSig
		case "NULLFAIL":
			flags |= ScriptVerifyNullFail
		case "P2SH":
			flags |= ScriptBip16
		case "SIGPUSHONLY":
			flags |= ScriptVerifySigPushOnly
		case "STRICTENC":
			flags |= ScriptVerifyStrictEncoding
		case "WITNESS":
			flags |= ScriptVerifyWitness
		case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
			flags |= ScriptVerifyDiscourageUpgradeableWitnessProgram
		case "MINIMALIF":
			flags |= ScriptVerifyMinimalIf
		case "WITNESS_PUBKEYTYPE":
			flags |= ScriptVerifyWitnessPubKeyType
		case "TAPROOT":
			flags |= ScriptVerifyTaproot
		case "CONST_SCRIPTCODE":
			flags |= ScriptVerifyConstScriptCode
		default:
			return flags, fmt.Errorf("invalid flag: %s", flag)
		}
	}
	return flags, nil
}

// parseExpectedResult parses the provided expected result string into allowed
// script error codes.  An error is returned if the expected result string is
// not supported.
func parseExpectedResult(expected string) ([]ErrorCode, error) {
	switch expected {
	case "OK":
		return nil, nil
	case "UNKNOWN_ERROR":
		return []ErrorCode{ErrNumberTooBig, ErrMinimalData}, nil
	case "PUBKEYTYPE":
		return []ErrorCode{ErrPubKeyType}, nil
	case "SIG_DER":
		return []ErrorCode{ErrSigTooShort, ErrSigTooLong,
			ErrSigInvalidSeqID, ErrSigInvalidDataLen, ErrSigMissingSTypeID,
			ErrSigMissingSLen, ErrSigInvalidSLen,
			ErrSigInvalidRIntID, ErrSigZeroRLen, ErrSigNegativeR,
			ErrSigTooMuchRPadding, ErrSigInvalidSIntID,
			ErrSigZeroSLen, ErrSigNegativeS, ErrSigTooMuchSPadding,
			ErrInvalidSigHashType}, nil
	case "EVAL_FALSE":
		return []ErrorCode{ErrEvalFalse, ErrEmptyStack}, nil
	case "EQUALVERIFY":
		return []ErrorCode{ErrEqualVerify}, nil
	case "NULLFAIL":
		return []ErrorCode{ErrNullFail}, nil
	case "SIG_HIGH_S":
		return []ErrorCode{ErrSigHighS}, nil
	case "SIG_HASHTYPE":
		return []ErrorCode{ErrInvalidSigHashType}, nil
	case "SIG_NULLDUMMY":
		return []ErrorCode{ErrSigNullDummy}, nil
	case "SIG_PUSHONLY":
		return []ErrorCode{ErrNotPushOnly}, nil
	case "CLEANSTACK":
		return []ErrorCode{ErrCleanStack}, nil
	case "BAD_OPCODE":
		return []ErrorCode{ErrReservedOpcode, ErrMalformedPush}, nil
	case "UNBALANCED_CONDITIONAL":
		return []ErrorCode{ErrUnbalancedConditional,
			ErrInvalidStackOperation}, nil
	case "OP_RETURN":
		return []ErrorCode{ErrEarlyReturn}, nil
	case "VERIFY":
		return []ErrorCode{ErrVerify}, nil
	case "INVALID_STACK_OPERATION", "INVALID_ALTSTACK_OPERATION":
		return []ErrorCode{ErrInvalidStackOperation}, nil
	case "DISABLED_OPCODE":
		return []ErrorCode{ErrDisabledOpcode}, nil
	case "DISCOURAGE_UPGRADABLE_NOPS":
		return []ErrorCode{ErrDiscourageUpgradableNOPs}, nil
	case "PUSH_SIZE":
		return []ErrorCode{ErrElementTooBig}, nil
	case "OP_COUNT":
		return []ErrorCode{ErrTooManyOperations}, nil
	case "STACK_SIZE":
		return []ErrorCode{ErrStackOverflow}, nil
	case "SCRIPT_SIZE":
		return []ErrorCode{ErrScriptTooBig}, nil
	case "PUBKEY_COUNT":
		return []ErrorCode{ErrInvalidPubKeyCount}, nil
	case "SIG_COUNT":
		return []ErrorCode{ErrInvalidSignatureCount}, nil
	case "MINIMALDATA":
		return []ErrorCode{ErrMinimalData}, nil
	case "NEGATIVE_LOCKTIME":
		return []ErrorCode{ErrNegativeLockTime}, nil
	case "UNSATISFIED_LOCKTIME":
		return []ErrorCode{ErrUnsatisfiedLockTime}, nil
	case "MINIMALIF":
		return []ErrorCode{ErrMinimalIf}, nil
	case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
		return []ErrorCode{ErrDiscourageUpgradableWitnessProgram}, nil
	case "WITNESS_PROGRAM_WRONG_LENGTH":
		return []ErrorCode{ErrWitnessProgramWrongLength}, nil
	case "WITNESS_PROGRAM_WITNESS_EMPTY":
		return []ErrorCode{ErrWitnessProgramEmpty}, nil
	case "WITNESS_PROGRAM_MISMATCH":
		return []ErrorCode{ErrWitnessProgramMismatch}, nil
	case "WITNESS_MALLEATED":
		return []ErrorCode{ErrWitnessMalleated}, nil
	case "WITNESS_MALLEATED_P2SH":
		return []ErrorCode{ErrWitnessMalleatedP2SH}, nil
	case "WITNESS_UNEXPECTED":
		return []ErrorCode{ErrWitnessUnexpected}, nil
	case "WITNESS_PUBKEYTYPE":
		return []ErrorCode{ErrWitnessPubKeyType}, nil
	}

	return nil, fmt.Errorf("unrecognized expected result in test data: %v",
		expected)
}

// createSpendTx generates a basic spending transaction given the passed
// signature, witness and public key scripts.
func createSpendingTx(witness [][]byte, sigScript, pkScript []byte,
	outputValue int64) *wire.MsgTx {

	coinbaseTx := wire.NewMsgTx(wire.TxVersion)

	outPoint := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	txIn := wire.NewTxIn(outPoint, []byte{OP_0, OP_0}, nil)
	txOut := wire.NewTxOut(outputValue, pkScript)
	coinbaseTx.AddTxIn(txIn)
	coinbaseTx.AddTxOut(txOut)

	spendingTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTxSha := coinbaseTx.TxHash()
	outPoint = wire.NewOutPoint(&coinbaseTxSha, 0)
	txIn = wire.NewTxIn(outPoint, sigScript, witness)
	txOut = wire.NewTxOut(outputValue, nil)

	spendingTx.AddTxIn(txIn)
	spendingTx.AddTxOut(txOut)

	return spendingTx
}

// scriptWithInputVal wraps a target pkScript with the value of the output in
// which it is contained. The inputVal is necessary in order to properly
// validate inputs which spend nested, or native witness programs.
type scriptWithInputVal struct {
	inputVal int64
	pkScript []byte
}

// TestScripts ensures all of the tests in script_tests.json execute with the
// expected results as defined in the test data.
func TestScripts(t *testing.T) {
	// Prepare the test cases.
	testCases, err := prepareScriptTestCases()
	require.NoError(t, err)

	sigCache := NewSigCache(10)

	// Run all script tests with and without the signature cache.
	for _, tc := range testCases {
		name := fmt.Sprintf("line %d", tc.lineNum)
		t.Run(name, func(t *testing.T) {
			testScriptCase(t, tc, nil)
		})

		name = fmt.Sprintf("line %d with cache", tc.lineNum)
		t.Run(name, func(t *testing.T) {
			testScriptCase(t, tc, sigCache)
		})
	}
}

// testVecF64ToUint32 properly handles conversion of float64s read from the JSON
// test data to unsigned 32-bit integers.  This is necessary because some of the
// test data uses -1 as a shortcut to mean max uint32 and direct conversion of a
// negative float to an unsigned int is implementation dependent and therefore
// doesn't result in the expected value on all platforms.  This function woks
// around that limitation by converting to a 32-bit signed integer first and
// then to a 32-bit unsigned integer which results in the expected behavior on
// all platforms.
func testVecF64ToUint32(f float64) uint32 {
	return uint32(int32(f))
}

// TestTxInvalidTests ensures all of the tests in tx_invalid.json fail as
// expected.
func TestTxInvalidTests(t *testing.T) {
	file, err := os.ReadFile("data/tx_invalid.json")
	if err != nil {
		t.Fatalf("TestTxInvalidTests: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestTxInvalidTests couldn't Unmarshal: %v\n", err)
	}

	// form is either:
	//   ["this is a comment "]
	// or:
	//   [[[previous hash, previous index, previous scriptPubKey]...,]
	//	serializedTransaction, verifyFlags]
testloop:
	for i, test := range tests {
		inputs, ok := test[0].([]interface{})
		if !ok {
			continue
		}

		if len(test) != 3 {
			t.Errorf("bad test (bad length) %d: %v", i, test)
			continue

		}
		serializedhex, ok := test[1].(string)
		if !ok {
			t.Errorf("bad test (arg 2 not string) %d: %v", i, test)
			continue
		}
		serializedTx, err := hex.DecodeString(serializedhex)
		if err != nil {
			t.Errorf("bad test (arg 2 not hex %v) %d: %v", err, i,
				test)
			continue
		}

		tx, err := btcutil.NewTxFromBytes(serializedTx)
		if err != nil {
			t.Errorf("bad test (arg 2 not msgtx %v) %d: %v", err,
				i, test)
			continue
		}

		verifyFlags, ok := test[2].(string)
		if !ok {
			t.Errorf("bad test (arg 3 not string) %d: %v", i, test)
			continue
		}

		flags, err := parseScriptFlags(verifyFlags)
		if err != nil {
			t.Errorf("bad test %d: %v", i, err)
			continue
		}

		prevOutFetcher := NewMultiPrevOutFetcher(nil)
		for j, iinput := range inputs {
			input, ok := iinput.([]interface{})
			if !ok {
				t.Errorf("bad test (%dth input not array)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			if len(input) < 3 || len(input) > 4 {
				t.Errorf("bad test (%dth input wrong length)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			previoustx, ok := input[0].(string)
			if !ok {
				t.Errorf("bad test (%dth input hash not string)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			prevhash, err := chainhash.NewHashFromStr(previoustx)
			if err != nil {
				t.Errorf("bad test (%dth input hash not hash %v)"+
					"%d: %v", j, err, i, test)
				continue testloop
			}

			idxf, ok := input[1].(float64)
			if !ok {
				t.Errorf("bad test (%dth input idx not number)"+
					"%d: %v", j, i, test)
				continue testloop
			}
			idx := testVecF64ToUint32(idxf)

			oscript, ok := input[2].(string)
			if !ok {
				t.Errorf("bad test (%dth input script not "+
					"string) %d: %v", j, i, test)
				continue testloop
			}

			script, err := parseShortForm(oscript)
			if err != nil {
				t.Errorf("bad test (%dth input script doesn't "+
					"parse %v) %d: %v", j, err, i, test)
				continue testloop
			}

			var inputValue float64
			if len(input) == 4 {
				inputValue, ok = input[3].(float64)
				if !ok {
					t.Errorf("bad test (%dth input value not int) "+
						"%d: %v", j, i, test)
					continue
				}
			}

			op := wire.NewOutPoint(prevhash, idx)
			prevOutFetcher.AddPrevOut(*op, &wire.TxOut{
				Value:    int64(inputValue),
				PkScript: script,
			})
		}

		for k, txin := range tx.MsgTx().TxIn {
			prevOut := prevOutFetcher.FetchPrevOutput(
				txin.PreviousOutPoint,
			)
			if prevOut == nil {
				t.Errorf("bad test (missing %dth input) %d:%v",
					k, i, test)
				continue testloop
			}
			// These are meant to fail, so as soon as the first
			// input fails the transaction has failed. (some of the
			// test txns have good inputs, too..
			vm, err := NewEngine(prevOut.PkScript, tx.MsgTx(), k,
				flags, nil, nil, prevOut.Value, prevOutFetcher)
			if err != nil {
				continue testloop
			}

			err = vm.Execute()
			if err != nil {
				continue testloop
			}

		}
		t.Errorf("test (%d:%v) succeeded when should fail",
			i, test)
	}
}

// TestTxValidTests ensures all of the tests in tx_valid.json pass as expected.
func TestTxValidTests(t *testing.T) {
	// Prepare the test cases.
	testCases, err := prepareTxValidTestCase()
	require.NoError(t, err)

	for _, tc := range testCases {
		name := fmt.Sprintf("line %d", tc.lineNum)
		t.Run(name, func(t *testing.T) {
			t.Logf("Running test case %s", spew.Sdump(tc))

			prevOutFetcher := NewMultiPrevOutFetcher(nil)
			for _, inp := range tc.inputs {
				op := wire.NewOutPoint(
					&inp.prevHash, inp.prevIdx,
				)
				prevOutFetcher.AddPrevOut(*op, &wire.TxOut{
					Value:    inp.amount,
					PkScript: inp.scriptPubKey,
				})
			}

			for k, txin := range tc.tx.MsgTx().TxIn {
				prevOut := prevOutFetcher.FetchPrevOutput(
					txin.PreviousOutPoint,
				)
				require.NotNil(t, prevOut)

				vm, err := NewEngine(
					prevOut.PkScript, tc.tx.MsgTx(), k,
					tc.flags, nil, nil, prevOut.Value,
					prevOutFetcher,
				)
				require.NoError(t, err, "failed to create vm")

				err = vm.Execute()
				require.NoError(t, err, "failed to execute vm")
			}
		})
	}
}

// TestCalcSignatureHash runs the Bitcoin Core signature hash calculation tests
// in sighash.json.
// https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json
func TestCalcSignatureHash(t *testing.T) {
	file, err := os.ReadFile("data/sighash.json")
	if err != nil {
		t.Fatalf("TestCalcSignatureHash: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestCalcSignatureHash couldn't Unmarshal: %v\n",
			err)
	}

	const scriptVersion = 0
	for i, test := range tests {
		if i == 0 {
			// Skip first line -- contains comments only.
			continue
		}
		if len(test) != 5 {
			t.Fatalf("TestCalcSignatureHash: Test #%d has "+
				"wrong length.", i)
		}
		var tx wire.MsgTx
		rawTx, _ := hex.DecodeString(test[0].(string))
		err := tx.Deserialize(bytes.NewReader(rawTx))
		if err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to parse transaction: %v", i, err)
			continue
		}

		subScript, _ := hex.DecodeString(test[1].(string))
		if err := checkScriptParses(scriptVersion, subScript); err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to parse sub-script: %v", i, err)
			continue
		}

		hashType := SigHashType(testVecF64ToUint32(test[3].(float64)))
		hash, err := CalcSignatureHash(subScript, hashType, &tx,
			int(test[2].(float64)))
		if err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to compute sighash: %v", i, err)
			continue
		}

		expectedHash, _ := chainhash.NewHashFromStr(test[4].(string))
		if !bytes.Equal(hash, expectedHash[:]) {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Signature hash mismatch.", i)
		}
	}
}

type inputWitness struct {
	ScriptSig string   `json:"scriptSig"`
	Witness   []string `json:"witness"`
}

type taprootJsonTest struct {
	Tx       string   `json:"tx"`
	Prevouts []string `json:"prevouts"`
	Index    int      `json:"index"`
	Flags    string   `json:"flags"`

	Comment string `json:"comment"`

	Success *inputWitness `json:"success"`

	Failure *inputWitness `json:"failure"`
}

func executeTaprootRefTest(t *testing.T, testCase taprootJsonTest) {
	t.Helper()

	txHex, err := hex.DecodeString(testCase.Tx)
	if err != nil {
		t.Fatalf("unable to decode hex: %v", err)
	}
	tx, err := btcutil.NewTxFromBytes(txHex)
	if err != nil {
		t.Fatalf("unable to decode hex: %v", err)
	}

	var prevOut wire.TxOut

	prevOutFetcher := NewMultiPrevOutFetcher(nil)
	for i, prevOutString := range testCase.Prevouts {
		prevOutBytes, err := hex.DecodeString(prevOutString)
		if err != nil {
			t.Fatalf("unable to decode hex: %v", err)
		}

		var txOut wire.TxOut
		err = wire.ReadTxOut(
			bytes.NewReader(prevOutBytes), 0, 0, &txOut,
		)
		if err != nil {
			t.Fatalf("unable to read utxo: %v", err)
		}

		prevOutFetcher.AddPrevOut(
			tx.MsgTx().TxIn[i].PreviousOutPoint, &txOut,
		)

		if i == testCase.Index {
			prevOut = txOut
		}
	}

	flags, err := parseScriptFlags(testCase.Flags)
	if err != nil {
		t.Fatalf("unable to parse flags: %v", err)
	}

	makeVM := func() *Engine {
		hashCache := NewTxSigHashes(tx.MsgTx(), prevOutFetcher)

		vm, err := NewEngine(
			prevOut.PkScript, tx.MsgTx(), testCase.Index,
			flags, nil, hashCache, prevOut.Value, prevOutFetcher,
		)
		if err != nil {
			t.Fatalf("unable to create vm: %v", err)
		}

		return vm
	}

	if testCase.Success != nil {
		tx.MsgTx().TxIn[testCase.Index].SignatureScript, err = hex.DecodeString(
			testCase.Success.ScriptSig,
		)
		if err != nil {
			t.Fatalf("unable to parse sig script: %v", err)
		}

		var witness [][]byte
		for _, witnessStr := range testCase.Success.Witness {
			witElem, err := hex.DecodeString(witnessStr)
			if err != nil {
				t.Fatalf("unable to parse witness stack: %v", err)
			}

			witness = append(witness, witElem)
		}

		tx.MsgTx().TxIn[testCase.Index].Witness = witness

		vm := makeVM()

		err = vm.Execute()
		if err != nil {
			t.Fatalf("test (%v) failed to execute: "+
				"%v", testCase.Comment, err)
		}
	}

	if testCase.Failure != nil {
		tx.MsgTx().TxIn[testCase.Index].SignatureScript, err = hex.DecodeString(
			testCase.Failure.ScriptSig,
		)
		if err != nil {
			t.Fatalf("unable to parse sig script: %v", err)
		}

		var witness [][]byte
		for _, witnessStr := range testCase.Failure.Witness {
			witElem, err := hex.DecodeString(witnessStr)
			if err != nil {
				t.Fatalf("unable to parse witness stack: %v", err)
			}

			witness = append(witness, witElem)
		}

		tx.MsgTx().TxIn[testCase.Index].Witness = witness

		vm := makeVM()

		err = vm.Execute()
		if err == nil {
			t.Fatalf("test (%v) succeeded, should fail: "+
				"%v", testCase.Comment, err)
		}
	}
}

// TestTaprootReferenceTests test that we're able to properly validate (success
// and failure paths for each test) the set of functional generative tests
// created by the bitcoind project for taproot at:
// https://github.com/bitcoin/bitcoin/blob/master/test/functional/feature_taproot.py.
func TestTaprootReferenceTests(t *testing.T) {
	t.Parallel()

	filePath := "data/taproot-ref"

	testFunc := func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.IsDir() {
			t.Logf("skipping dir: %v", info.Name())
			return nil
		}

		testJson, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read file: %v", err)
		}

		// All the JSON files have a trailing comma and a new line
		// character, so we'll remove that here before attempting to
		// parse it.
		testJson = bytes.TrimSuffix(testJson, []byte(",\n"))

		var testCase taprootJsonTest
		if err := json.Unmarshal(testJson, &testCase); err != nil {
			return fmt.Errorf("unable to decode json: %v", err)
		}

		testName := fmt.Sprintf(
			"%v:%v", testCase.Comment, filepath.Base(path),
		)
		_ = t.Run(testName, func(t *testing.T) {
			t.Parallel()

			executeTaprootRefTest(t, testCase)
		})

		return nil
	}

	err := filepath.Walk(filePath, testFunc)
	if err != nil {
		t.Fatalf("unable to execute taproot test vectors: %v", err)
	}
}

// scriptTestCase defines a test case to run against the script engine.
type scriptTestCase struct {
	lineNum      int
	witness      [][]byte
	amount       btcutil.Amount
	scriptSig    []byte
	scriptPubKey []byte
	flags        ScriptFlags
	errCodes     []ErrorCode
	comment      string

	// raw is the original line, useful for debugging.
	raw interface{}
}

// prepareScriptTestCases reads the `script_tests.json` file, parses it and
// returns a slice of scriptTestCase structs.
func prepareScriptTestCases() ([]*scriptTestCase, error) {
	file, err := os.ReadFile("data/script_tests.json")
	if err != nil {
		return nil, fmt.Errorf("failed to parse json %w", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal: %v", err)
	}

	testCases := make([]*scriptTestCase, 0, len(tests))
	for i, test := range tests {
		// Skip single line comments.
		if len(test) == 1 {
			continue
		}

		tc, err := parseScriptTestCase(test)
		if err != nil {
			return nil, fmt.Errorf("parse test case %d: %v", i, err)
		}

		// Remember the line num for debugging.
		tc.lineNum = i + 1
		testCases = append(testCases, tc)
	}

	return testCases, nil
}

// parseScriptTestCase takes one line from the json file and parses it into a
// scriptTestCase. Each line has at most 6 items and at least 4 items, listed
// below,
// 1. Witness data and amount, optional.
// 2. scriptSig.
// 3. scriptPubKey.
// 4. Flags.
// 5. Expected error code.
// 6. Comment, optional.
func parseScriptTestCase(line []interface{}) (*scriptTestCase, error) {
	// The line must have at least 4 items and at most 6 items.
	if len(line) < 4 || len(line) > 6 {
		return nil, fmt.Errorf("corrupted line: %v", line)
	}

	var (
		witnessStr      []interface{}
		scriptSigStr    string
		scriptPubKeyStr string
		flagsStr        string
		errCodeStr      string
		comment         string
	)

	// We now parse the line based on the number of items found.
	switch len(line) {
	// If there are exactly four items, they must be,
	// - scriptSig.
	// - scriptPubKey.
	// - Flags.
	// - Expected error code.
	case 4:
		scriptSigStr = line[0].(string)
		scriptPubKeyStr = line[1].(string)
		flagsStr = line[2].(string)
		errCodeStr = line[3].(string)

	// If there are six items, they must be exactly 6 items in the order,
	// - Witness data.
	// - scriptSig.
	// - scriptPubKey.
	// - Flags.
	// - Expected error code.
	// - Comment.
	case 6:
		witnessStr = line[0].([]interface{})
		scriptSigStr = line[1].(string)
		scriptPubKeyStr = line[2].(string)
		flagsStr = line[3].(string)
		errCodeStr = line[4].(string)
		comment = line[5].(string)

	// If there are five items, we need to know whether the first item is
	// witness data or not to parse the rest.
	default:
		offset := 0

		// If the first item is a slice, it must be witness data.
		firstItem, ok := line[0].([]interface{})
		if ok {
			witnessStr = firstItem
			offset++
		} else {
			// If the first item is not a slice, then the last item
			// must be a comment.
			comment = line[4].(string)
		}

		scriptSigStr = line[offset].(string)
		scriptPubKeyStr = line[offset+1].(string)
		flagsStr = line[offset+2].(string)
		errCodeStr = line[offset+3].(string)
	}

	// Init a test case.
	tc := &scriptTestCase{}

	// We have parsed out the items in string, and now we can parse them
	// into types.
	if len(witnessStr) > 0 {
		// If this is a witness test, then the final element
		// within the slice is the input amount, so we ignore
		// all but the last element in order to parse the
		// witness stack.
		strWitnesses := witnessStr[:len(witnessStr)-1]
		witness, err := parseWitnessStack(strWitnesses)
		if err != nil {
			return nil, fmt.Errorf("can't parse witness; %w", err)
		}

		amt, err := btcutil.NewAmount(
			witnessStr[len(witnessStr)-1].(float64),
		)
		if err != nil {
			return nil, fmt.Errorf("can't parse input amt: %w", err)
		}

		tc.witness = witness
		tc.amount = amt
	}

	// Parse the scriptSig.
	scriptSig, err := parseShortForm(scriptSigStr)
	if err != nil {
		return nil, fmt.Errorf("can't parse signature script: %w", err)
	}

	// Parse the scriptPubKey.
	scriptPubKey, err := parseShortForm(scriptPubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("can't parse scriptPubKey: %w", err)
	}

	// Parse the flags.
	flags, err := parseScriptFlags(flagsStr)
	if err != nil {
		return nil, fmt.Errorf("can't parse flags %w", err)
	}

	// Parse the expected error code.
	allowedErrorCodes, err := parseExpectedResult(errCodeStr)
	if err != nil {
		return nil, fmt.Errorf("can't parse error code: %w", err)
	}

	// Set the parsed values into the test case.
	tc.scriptSig = scriptSig
	tc.scriptPubKey = scriptPubKey
	tc.flags = flags
	tc.errCodes = allowedErrorCodes
	tc.comment = comment

	// Save the raw str for debugging.
	tc.raw = struct {
		witness      []interface{}
		scriptSig    string
		scriptPubKey string
		flags        string
		errCode      string
		comment      string
	}{
		witness:      witnessStr,
		scriptSig:    scriptSigStr,
		scriptPubKey: scriptPubKeyStr,
		flags:        flagsStr,
		errCode:      errCodeStr,
		comment:      comment,
	}

	return tc, nil
}

// testScriptCase runs the test over a single scriptTestCase.
func testScriptCase(t *testing.T, tc *scriptTestCase, sigCache *SigCache) {
	t.Logf("Running test case %s", spew.Sdump(tc))

	// Generate a transaction pair such that one spends from the other and
	// the provided signature and public key scripts are used, then create
	// a new engine to execute the scripts.
	tx := createSpendingTx(
		tc.witness, tc.scriptSig, tc.scriptPubKey, int64(tc.amount),
	)
	prevOuts := NewCannedPrevOutputFetcher(
		tc.scriptPubKey, int64(tc.amount),
	)

	// Create a testing engine.
	vm, err := NewEngine(
		tc.scriptPubKey, tx, 0, tc.flags, sigCache, nil,
		int64(tc.amount), prevOuts,
	)

	// Execute the script engine and check the expected error is returned.
	//
	// TODO(yy): differentiate the creation err vs execution err?
	if err == nil {
		err = vm.Execute()
	}

	// Ensure there were no errors when the expected result is OK.
	if tc.errCodes == nil {
		require.NoError(t, err, "failed to create/execute engine")
		return
	}

	// At this point an error was expected so ensure the result of the
	// execution matches it.
	//
	// We expect the returned err is the defined type.
	serr, ok := err.(Error)
	require.True(t, ok, "error is not a script error")

	// We expect the returned error code is contained in the expected error
	// code list.
	require.Contains(t, tc.errCodes, serr.ErrorCode, "returned "+
		"unexpected error code, want %v, got %v, desc: %v", tc.errCodes,
		serr.ErrorCode, serr)
}

// testInput defines a single test input.
type testInput struct {
	prevHash     chainhash.Hash
	prevIdx      uint32
	scriptPubKey []byte
	amount       int64
}

// txValidTestCase is a test case for a valid transaction.
type txValidTestCase struct {
	lineNum int
	inputs  []*testInput
	tx      *btcutil.Tx
	flags   ScriptFlags

	comment string

	// raw is the original line, useful for debugging.
	raw interface{}
}

// prepareTxValidTestCase reads the `tx_valid.json` file, parses it and
// returns a slice of scriptTestCase structs.
func prepareTxValidTestCase() ([]*txValidTestCase, error) {
	file, err := os.ReadFile("data/tx_valid.json")
	if err != nil {
		return nil, fmt.Errorf("failed to parse json %w", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal: %v", err)
	}

	comment := ""

	testCases := make([]*txValidTestCase, 0, len(tests))
	for i, test := range tests {
		// Add the comments.
		if len(test) == 1 {
			comment += test[0].(string)
			comment += "\n"
			continue
		}

		tc, err := parseTxValidTestCase(test)
		if err != nil {
			return nil, fmt.Errorf("parse test case %d: %v", i, err)
		}

		// Remember the line num for debugging.
		tc.lineNum = i + 1

		// Attach the comments.
		tc.comment = comment
		testCases = append(testCases, tc)

		// Reset the comments.
		comment = ""
	}

	return testCases, nil
}

// parseTxValidTestCase takes one line from the json file and parses it into a
// txValidTestCase. Each line has exactly 3 items, listed below,
// 1. input(s).
// 2. serialized tx.
// 3. excluded verifyFlags.
func parseTxValidTestCase(line []interface{}) (*txValidTestCase, error) {
	// The line must have exactly 3 items.
	if len(line) != 3 {
		return nil, fmt.Errorf("corrupted line: %v", line)
	}

	var (
		inputsStr       []interface{}
		serializedTxStr string
		flagsStr        string
	)

	// Parse inputs.
	inputsStr = line[0].([]interface{})

	inputs := make([]*testInput, 0)
	for _, item := range inputsStr {
		inp := item.([]interface{})

		// Each input should have three or four items,
		// - prevHash
		// - prevIdx
		// - scriptPubKey
		// - amount (optional).
		if len(inp) < 3 || len(inp) > 4 {
			return nil, fmt.Errorf("corrupted input: %v", inp)
		}

		// Parse the prevHash.
		prevHashStr := inp[0].(string)
		prevHash, err := chainhash.NewHashFromStr(prevHashStr)
		if err != nil {
			return nil, err
		}

		// Parse the prevIdx.
		idxf := inp[1].(float64)
		idx := testVecF64ToUint32(idxf)

		// Parse the scriptPubKey.
		scriptPubKeyStr := inp[2].(string)
		scriptPubKey, err := parseShortForm(scriptPubKeyStr)

		// Parse the amount.
		var amount int64
		if len(inp) == 4 {
			amount = int64(inp[3].(float64))
		}

		inputs = append(inputs, &testInput{
			prevHash:     *prevHash,
			prevIdx:      idx,
			scriptPubKey: scriptPubKey,
			amount:       amount,
		})
	}

	// Parse the serialized tx.
	serializedTxStr = line[1].(string)
	serializedTx, err := hex.DecodeString(serializedTxStr)
	if err != nil {
		return nil, err
	}

	tx, err := btcutil.NewTxFromBytes(serializedTx)
	if err != nil {
		return nil, err
	}

	// Parse the excluded flags.
	flagsStr = line[2].(string)
	excludedFlags, err := parseScriptFlags(flagsStr)
	if err != nil {
		return nil, err
	}

	var allFlags ScriptFlags
	for i := 1; i < int(scriptSentinal); i = i << 1 {
		flag := ScriptFlags(i)
		allFlags |= flag
	}
	flags := allFlags ^ excludedFlags

	// Create the test case.
	tc := &txValidTestCase{
		inputs: inputs,
		tx:     tx,
		flags:  flags,
	}

	// Save the raw str for debugging.
	tc.raw = struct {
		inputs        []interface{}
		txHex         string
		excludedFlags string
	}{
		inputs:        inputsStr,
		txHex:         serializedTxStr,
		excludedFlags: flagsStr,
	}

	return tc, nil
}
