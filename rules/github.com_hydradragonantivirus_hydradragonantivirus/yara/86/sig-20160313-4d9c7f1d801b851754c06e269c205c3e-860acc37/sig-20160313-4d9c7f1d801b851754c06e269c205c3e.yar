rule sig_20160313_4d9c7f1d801b851754c06e269c205c3e {
  meta:
    description = "datamaliciousorder - file 20160313_4d9c7f1d801b851754c06e269c205c3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da0f91a0f709ecb6e5973f036ea163f687e0042e7546d223a75503ec16ec4fe1"

  strings:
    $s1  = "return INIqHVD[0] + INIqHVD[2] + INIqHVD[4] + \".F\" + INIqHVD[7] + INIqHVD[9] + INIqHVD[12] + INIqHVD[14];" fullword ascii
    $s2  = "var US = true  , aWZM = HgV[7] + HgV[9] + HgV[11];" fullword ascii
    $s3  = "var HgV = (\"2.XMLHTTP ypkDWVM PidQn XML ream St fPAqIVXP AD RxOIUBc O zfbO D\").split(\" \");" fullword ascii
    $s4  = "var INIqHVD = \"Sc eqFdAXN r NCvRMlZrZ ipting AlxEFUB baf ile RBFUJfTkVajqwG System TP NoASP Obj Rivklu ect BGUzFMX\".split(\" " ascii
    $s5  = "VWHFC.open(hVzQb,FfjkV,false);" fullword ascii
    $s6  = "ieq = s; break; " fullword ascii
    $s7  = "function cIDfT(NrUBBa) {" fullword ascii
    $s8  = "if (aIPcR > 154158-935){return true;} else {return false;}" fullword ascii
    $s9  = "function dnnH(UHYlI) {" fullword ascii
    $s10 = "function oYYe(VWHFC,FfjkV,hVzQb) {" fullword ascii
    $s11 = "function TTbF(EElxL) {" fullword ascii
    $s12 = "function ETwt(JQzPG) {" fullword ascii
    $s13 = "return bwio.responseBody;" fullword ascii
    $s14 = "function EihH(LCppY) {" fullword ascii
    $s15 = "return THvIf;" fullword ascii
    $s16 = "return ATbfXYr(uD,pvKAR[294-288]+pvKAR[1000-993]+pvKAR[679-671]);" fullword ascii
    $s17 = "return JjBOd.status;" fullword ascii
    $s18 = "function RABA(UgIDW,fJCYP) {" fullword ascii
    $s19 = "function yRWw(MELHE,nngzC) {" fullword ascii
    $s20 = "function vlrBEqALY(smVdcrZsXCR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}