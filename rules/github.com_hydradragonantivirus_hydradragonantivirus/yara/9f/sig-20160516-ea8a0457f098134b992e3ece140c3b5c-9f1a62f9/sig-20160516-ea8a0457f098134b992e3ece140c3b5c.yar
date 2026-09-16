rule sig_20160516_ea8a0457f098134b992e3ece140c3b5c {
  meta:
    description = "datamaliciousorder - file 20160516_ea8a0457f098134b992e3ece140c3b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e62d4e60a5a463927022a0c4e8e60fc3c2e2ef4c19db5a8140c83cc18a2b72a2"

  strings:
    $s1  = "function eUgETW() {" fullword ascii
    $s2  = "while (CaHzAbgr < bKuxszu - (2284 + 1574 - 3856)) {" fullword ascii
    $s3  = "function com() {" fullword ascii
    $s4  = "return trCGxa;" fullword ascii
    $s5  = "return HiGoMYWN;" fullword ascii
    $s6  = "function fMyhbj() {" fullword ascii
    $s7  = "function szE() {" fullword ascii
    $s8  = "return DdgAHGS;" fullword ascii
    $s9  = "function rjB() {" fullword ascii
    $s10 = "return oscxy;" fullword ascii
    $s11 = "function jWpvZsK() {" fullword ascii
    $s12 = "return kuMLcsE;" fullword ascii
    $s13 = "function btW() {" fullword ascii
    $s14 = "function LrKK() {" fullword ascii
    $s15 = "return aSNr;" fullword ascii
    $s16 = "function gSeppf() {" fullword ascii
    $s17 = "function hLPZRMo(awWyIFe) {" fullword ascii
    $s18 = "function WRGOW() {" fullword ascii
    $s19 = "return RXAuGQ;" fullword ascii
    $s20 = "function lgOb() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}