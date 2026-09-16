rule sig_20160429_d6b0bf3782a9866e9e7b82b255331feb {
  meta:
    description = "datamaliciousorder - file 20160429_d6b0bf3782a9866e9e7b82b255331feb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df80c67bdd7c5b240a6a43f8e1a9bebc028d51c49c7d202cc0bf6a2cd765bac"

  strings:
    $s1  = "while (fvL < eBEkN - (6397, 8965, 746, 5242, 9400, 9801, 5097, 2588, 2)) {" fullword ascii
    $s2  = "return AJuPvdc + PyjcuSil + HjbcK + JBSkZQm + qVfgqii + YHs;" fullword ascii
    $s3  = "if (3 == true) {" fullword ascii
    $s4  = "if (1 == false) {" fullword ascii
    $s5  = "if (7 == true) {" fullword ascii
    $s6  = "if (1 === true) {" fullword ascii
    $s7  = "function Twv() {" fullword ascii
    $s8  = "return oScUu;" fullword ascii
    $s9  = "return QaBxYb;" fullword ascii
    $s10 = "function dKmT(kOl) {" fullword ascii
    $s11 = "function nPgG(giZi) {" fullword ascii
    $s12 = "var MEEu = true;" fullword ascii
    $s13 = "var FleESVK = false;" fullword ascii
    $s14 = "var UZTBsc = false;" fullword ascii
    $s15 = "var eSn = String;" fullword ascii
    $s16 = "function xHjKxqr() {" fullword ascii
    $s17 = "var ibHcck = false;" fullword ascii
    $s18 = "function beNxO() {" fullword ascii
    $s19 = "if (rRKkF === false) {" fullword ascii
    $s20 = "return xaMrGZ;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}