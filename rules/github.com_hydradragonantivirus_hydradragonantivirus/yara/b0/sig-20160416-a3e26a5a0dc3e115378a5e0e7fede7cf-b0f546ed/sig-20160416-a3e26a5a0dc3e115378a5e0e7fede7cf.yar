rule sig_20160416_a3e26a5a0dc3e115378a5e0e7fede7cf {
  meta:
    description = "datamaliciousorder - file 20160416_a3e26a5a0dc3e115378a5e0e7fede7cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ca4c4bf5d4d8b2e45e662e350c942be3ca0d135d87124f7e5aa62c6d33b7bd"

  strings:
    $s1  = "while (rAutkFCY < yVbuF - (7288, 3270, 7263, 470, 3456, 523, 41, 7209, 1018, 2421, 6320, 2)) {" fullword ascii
    $s2  = "return OhWuN + uMfkXrSO;" fullword ascii
    $s3  = "switch (\"1\") {" fullword ascii
    $s4  = "switch (\"0\") {" fullword ascii
    $s5  = "okVYggI(16721, true, false, \"0\");" fullword ascii
    $s6  = "return AcJki;" fullword ascii
    $s7  = "function zoEPQW(iJL, NyVpVT) {" fullword ascii
    $s8  = "var oHNTGB = false;" fullword ascii
    $s9  = "var YoXPrVi = false;" fullword ascii
    $s10 = "var tbLzO = true;" fullword ascii
    $s11 = "if (vCVUW === true) {" fullword ascii
    $s12 = "var tuaJRlz = false;" fullword ascii
    $s13 = "function njNdnfI() {" fullword ascii
    $s14 = "var vCVUW = true;" fullword ascii
    $s15 = "var lhii = true;" fullword ascii
    $s16 = "if (JRNBJ == false) {" fullword ascii
    $s17 = "var oHez = true;" fullword ascii
    $s18 = "if (yHgs === true) {" fullword ascii
    $s19 = "var ZwSa = false;" fullword ascii
    $s20 = "var YOBHrv = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}