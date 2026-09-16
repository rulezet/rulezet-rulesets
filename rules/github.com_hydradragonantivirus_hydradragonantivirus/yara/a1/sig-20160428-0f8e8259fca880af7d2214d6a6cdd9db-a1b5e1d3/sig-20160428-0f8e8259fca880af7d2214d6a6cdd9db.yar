rule sig_20160428_0f8e8259fca880af7d2214d6a6cdd9db {
  meta:
    description = "datamaliciousorder - file 20160428_0f8e8259fca880af7d2214d6a6cdd9db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ac252879a427defb17922e3d6d19ada656d37956d5483cc08fcc6c1cc47997"

  strings:
    $s1  = "return VEyENc + sCWXECr + EVDO + oNaU + JErc + UYYsD;" fullword ascii
    $s2  = "while (fXbXIa < HUZPV - (5671, 4472, 775, 5274, 4722, 2)) {" fullword ascii
    $s3  = "if (6 === false) {" fullword ascii
    $s4  = "if (4 === false) {" fullword ascii
    $s5  = "if (6 == false) {" fullword ascii
    $s6  = "if (4 == false) {" fullword ascii
    $s7  = "if (4 == true) {" fullword ascii
    $s8  = "if (7 === true) {" fullword ascii
    $s9  = "function PbVtjL() {" fullword ascii
    $s10 = "lfdd[vVTaC(\"060000012058\")](lgldr, kfkm, false);" fullword ascii
    $s11 = "var RgWDQsQ = true;" fullword ascii
    $s12 = "if (zqMYvR(0) != true) {" fullword ascii
    $s13 = "function FFSDK(hzMR, lMDZeE) {" fullword ascii
    $s14 = "function sMADoek() {" fullword ascii
    $s15 = "return vueXqbB;" fullword ascii
    $s16 = "return lkzS;" fullword ascii
    $s17 = "return tRGjt;" fullword ascii
    $s18 = "return GbgvPgmt[(6140, 6047, 5994, 2935, 4356, 5659, 5524, 7375, 6)];" fullword ascii
    $s19 = "return BtUUGXLr;" fullword ascii
    $s20 = "function lupD(GwDZkWn) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}