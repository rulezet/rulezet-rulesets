rule sig_20160428_34e3c86e5f63c0160c70d51973208599 {
  meta:
    description = "datamaliciousorder - file 20160428_34e3c86e5f63c0160c70d51973208599.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e5f355ede09f3eccf913e7c7c2eb1a4b8caf6d667a4ae18ab65d870e3f92a92"

  strings:
    $s1  = "while (UPCuKiR < eiZfBtrU - (6778, 4280, 7623, 3503, 6857, 3682, 2)) {" fullword ascii
    $s2  = "return rjtrS + jZWG + iHAqv + AQCitdQ + cVJ + DgHN;" fullword ascii
    $s3  = "if (3 == false) {" fullword ascii
    $s4  = "if (6 == true) {" fullword ascii
    $s5  = "if (6 == false) {" fullword ascii
    $s6  = "if (5 == false) {" fullword ascii
    $s7  = "if (5 === false) {" fullword ascii
    $s8  = "function TCqQF() {" fullword ascii
    $s9  = "function EQdj() {" fullword ascii
    $s10 = "return leDgHNs;" fullword ascii
    $s11 = "return JUq;" fullword ascii
    $s12 = "var dcGRH = false;;" fullword ascii
    $s13 = "var cEGgleNK = String;" fullword ascii
    $s14 = "function fkUWpQL() {" fullword ascii
    $s15 = "function gQel(dfegg) {" fullword ascii
    $s16 = "function WPz(RtFR) {" fullword ascii
    $s17 = "return WsTciY;" fullword ascii
    $s18 = "function lujpgfr() {" fullword ascii
    $s19 = "function evvMj(iTUBlx, GTyc) {" fullword ascii
    $s20 = "var GQCQK = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}