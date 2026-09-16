rule sig_20160513_19c630d6273793b202b703010f5b5203 {
  meta:
    description = "datamaliciousorder - file 20160513_19c630d6273793b202b703010f5b5203.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0694110f4d991a23df11c6686a1f1467008698479a85ab17156fa6a4614578d"

  strings:
    $s1  = "while (BaPN < olrmnA - (9031 - 9029)) {" fullword ascii
    $s2  = "var iSzQHb = [(vVfV())][(9968 + 1777 - 11745)](GAol);" fullword ascii
    $s3  = "return WEAifh;" fullword ascii
    $s4  = "function iJRmGM(GAol) {" fullword ascii
    $s5  = "function phHAbi() {" fullword ascii
    $s6  = "return ajURaFwb;" fullword ascii
    $s7  = "function KGCDDp(xZc, fSqAF) {" fullword ascii
    $s8  = "function TjYXTsU() {" fullword ascii
    $s9  = "function ifLARd() {" fullword ascii
    $s10 = "if (phHAbi(1) != true) {" fullword ascii
    $s11 = "function GZd() {" fullword ascii
    $s12 = "skHr = true;" fullword ascii
    $s13 = "return pHmApj;" fullword ascii
    $s14 = "function OVme(aDRU) {" fullword ascii
    $s15 = "function bAbcowO() {" fullword ascii
    $s16 = "function EuFV(rwH, TkfVry) {" fullword ascii
    $s17 = "return WkKGvCfV;" fullword ascii
    $s18 = "return KEbzuOpm;" fullword ascii
    $s19 = "function aerM() {" fullword ascii
    $s20 = "return MpUPlH;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}