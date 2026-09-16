rule sig_20160516_8287819d458bb2944397e71e0f788726 {
  meta:
    description = "datamaliciousorder - file 20160516_8287819d458bb2944397e71e0f788726.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24db4192e2020143e3989fdd6a0aebe8fa889032f06db001f0ca9ef847e4c89f"

  strings:
    $s1  = "while (Ptys < MwuHVM - (5836 + 1503 - 7337)) {" fullword ascii
    $s2  = "var aPzMj = true;" fullword ascii
    $s3  = "var QICIo = true;" fullword ascii
    $s4  = "function eanWtPg() {" fullword ascii
    $s5  = "if (sMvXUt === false) {" fullword ascii
    $s6  = "return bLHOz;" fullword ascii
    $s7  = "var zkdMNA = false;" fullword ascii
    $s8  = "function FIlH() {" fullword ascii
    $s9  = "function bPiNt() {" fullword ascii
    $s10 = "function WoPjNEr() {" fullword ascii
    $s11 = "function tOPB() {" fullword ascii
    $s12 = "var IODdP = false;" fullword ascii
    $s13 = "function XQjND() {" fullword ascii
    $s14 = "return SlkZ;" fullword ascii
    $s15 = "return tRFMAB;" fullword ascii
    $s16 = "if (mCxR == false) {" fullword ascii
    $s17 = "return qUrYHhXJ;" fullword ascii
    $s18 = "var SgJZmsL = false;" fullword ascii
    $s19 = "return sYlwM;" fullword ascii
    $s20 = "function OsSABlO(YNAzxaLG, BlzR) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}