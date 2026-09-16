rule sig_20160516_2c0977194c24e99924a8b8f878a1081d {
  meta:
    description = "datamaliciousorder - file 20160516_2c0977194c24e99924a8b8f878a1081d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52e00131a34b9999153e775b331bd995680b315e4f09fb9107f5f8fcb1965890"

  strings:
    $s1  = "while (nfbJ < JziWdWEm - (5980 + 1954 - 7932)) {" fullword ascii
    $s2  = "function bHOM(wsnuwW, dILZVc, VZjha, DLL) {" fullword ascii
    $s3  = "function RHMenhD() {" fullword ascii
    $s4  = "return csQEMDx;" fullword ascii
    $s5  = "return nTWUdZ;" fullword ascii
    $s6  = "return rFjtJ;" fullword ascii
    $s7  = "return wfDmAOMn;" fullword ascii
    $s8  = "return SUnhYVHu;" fullword ascii
    $s9  = "var oeSDkiS = String;" fullword ascii
    $s10 = "return RgVjI;" fullword ascii
    $s11 = "function rdeO() {" fullword ascii
    $s12 = "return Ofga;" fullword ascii
    $s13 = "function RlOSHy() {" fullword ascii
    $s14 = "function yezW(str) {" fullword ascii
    $s15 = "function qtRD() {" fullword ascii
    $s16 = "return Cgdu;" fullword ascii
    $s17 = "if (bHOM(749, 0, true, 534) == false) {" fullword ascii
    $s18 = "return uyVzI;" fullword ascii
    $s19 = "return hIKSZ;" fullword ascii
    $s20 = "return hnKcE;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}