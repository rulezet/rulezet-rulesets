rule sig_20160428_e1c18a51cb4fc7f6524626f4f3b70aed {
  meta:
    description = "datamaliciousorder - file 20160428_e1c18a51cb4fc7f6524626f4f3b70aed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d14e334da50d806db419ae9d541b40b2b44bd7a4a73a211722381e2e4306186"

  strings:
    $s1  = "while (Dkjdwst < tqNuT - (5750, 8639, 3929, 1761, 5505, 209, 1549, 2568, 2)) {" fullword ascii
    $s2  = "return UAYJmz + nqZ + JjvJhi + XYQ + RtmRNTJ + uDbsno;" fullword ascii
    $s3  = "if (5 === true) {" fullword ascii
    $s4  = "if (5 === false) {" fullword ascii
    $s5  = "if (6 === true) {" fullword ascii
    $s6  = "function XnLGURG() {" fullword ascii
    $s7  = "if (UjI == true) {" fullword ascii
    $s8  = "function vJkiF() {" fullword ascii
    $s9  = "var DeqPf = false;" fullword ascii
    $s10 = "function szTQD(xGPwElgY, RbQZxm) {" fullword ascii
    $s11 = "var wVaaWiH = false;" fullword ascii
    $s12 = "return RgS;" fullword ascii
    $s13 = "function EPgZuKB(zXCNP, rZfrEx) {" fullword ascii
    $s14 = "var sTuLA = true;" fullword ascii
    $s15 = "var gvDmO = true;" fullword ascii
    $s16 = "return TlWV;" fullword ascii
    $s17 = "function KDxL() {" fullword ascii
    $s18 = "return nUD;" fullword ascii
    $s19 = "function OQkL(dfegg) {" fullword ascii
    $s20 = "return XbSM;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}