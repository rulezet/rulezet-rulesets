rule sig_20160329_28357d7a1ce0a51968e575f9a7052775 {
  meta:
    description = "datamaliciousorder - file 20160329_28357d7a1ce0a51968e575f9a7052775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38f52720f42d4692d07ab15fd4625956b5a08bf532236a7b2df65029dab3d5b0"

  strings:
    $s1  = "for (setRequestHeader = (grep / (Math.pow(3, isDefaultPrevented) - 5)); setRequestHeader < response[rmargin + \"eng\" + rkeyEven" ascii
    $s2  = "for (setRequestHeader = (grep / (Math.pow(3, isDefaultPrevented) - 5)); setRequestHeader < response[rmargin + \"eng\" + rkeyEven" ascii
    $s3  = "beforeunload(\"response%20%3D%20%5BinnerHTML%20+%20%222.S%22%20+%20nodeIndex%20+%20%22MLHTTP%22%20+%20udataCur%20+%20%220%22%2C%" ascii
    $s4  = "val[rkeyEvent + \"yp\" + ignored] = ((scale & 13), (shift, 113, getAttribute, 199), (push * 1));" fullword ascii
    $s5  = "beforeunload(\"unwrap%28%22http%3A%22%20+%20booleans%20+%20%22oroos%22%20+%20sortDetached%20+%20%22om/%22%20+%20tweener%20+%20%2" ascii
    $s6  = "val[rnoInnerhtml + \"eToF\" + andSelf](disconnectedMatch, ((wrap - 60) / (whitespace - 34)));" fullword ascii
    $s7  = "val[rbuggyMatches + \"de\"] = ((30 - swing), (39 * rbrace + 9), (iNoClone & 3));" fullword ascii
    $s8  = "beforeunload(\"response%20%3D%20%5BinnerHTML%20+%20%222.S%22%20+%20nodeIndex%20+%20%22MLHTTP%22%20+%20udataCur%20+%20%220%22%2C%" ascii
    $s9  = "guaranteedUnique(version, slow, completed, tweener);" fullword ascii
    $s10 = "qualifier(init, completed, fail, a, statusText);" fullword ascii
    $s11 = "function rnoContent() {" fullword ascii
    $s12 = "function startLength(splice, matcherFromTokens, finalDataType) {" fullword ascii
    $s13 = "beforeunload(\"unwrap%28%22http%3A%22%20+%20booleans%20+%20%22oroos%22%20+%20sortDetached%20+%20%22om/%22%20+%20tweener%20+%20%2" ascii
    $s14 = "function rootjQuery(documentIsHTML) {" fullword ascii
    $s15 = "function rejectWith(linear, getClass, mouseleave) {" fullword ascii
    $s16 = "function unwrap() {" fullword ascii
    $s17 = "structure();" fullword ascii
    $s18 = "if (maxWidth[slow] == ((newSelector & 250))) {" fullword ascii
    $s19 = "function guaranteedUnique(unqueued) {" fullword ascii
    $s20 = "function opts(isFunction, argument) {" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}