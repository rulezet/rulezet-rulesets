rule sig_20160307_52010dafdd402985fc3b19abdee95830 {
  meta:
    description = "datamaliciousorder - file 20160307_52010dafdd402985fc3b19abdee95830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a68aeb64607a23e8375481f00bef559dc35180710203b447cbdf6ee6efb4540"

  strings:
    $s1  = "return SjvjNls[0] + SjvjNls[2] + SjvjNls[4] + \".F\" + SjvjNls[7] + SjvjNls[9] + SjvjNls[12] + SjvjNls[14];" fullword ascii
    $s2  = "var dn = true  , ZtFN = DoD[7] + DoD[9] + DoD[11];" fullword ascii
    $s3  = "var SjvjNls = \"Sc inxRoUw r DESMCNCyJ ipting cQJQilk gxT ile LgDkoovJpfksob System LD vTynk Obj WQZnbX ect YrYzFcl\".split(\" " ascii
    $s4  = "var DoD = (\"2.XMLHTTP nWiVeqF NUitm XML ream St brzOgtAR AD mNOBJQL O LgmB D\").split(\" \");" fullword ascii
    $s5  = "return nJ.ExpandEnvironmentStrings(JGgtV[6]+JGgtV[7]+JGgtV[8]);" fullword ascii
    $s6  = "return ZIfa.responseBody;" fullword ascii
    $s7  = "wgb = D; break; " fullword ascii
    $s8  = "if(D>=o.length) {break;}" fullword ascii
    $s9  = "function GpYg(cGWnP) {" fullword ascii
    $s10 = "function pdHf(WaObN) {" fullword ascii
    $s11 = "return NQZ.size;" fullword ascii
    $s12 = "return new ActiveXObject(nHOGtE);" fullword ascii
    $s13 = "if (nMxum > 190842-678){return true;} else {return false;}" fullword ascii
    $s14 = "function TgrmjglW() {" fullword ascii
    $s15 = "return tPanCkt" fullword ascii
    $s16 = "function DNTh(RNUIy) {" fullword ascii
    $s17 = "if (cyDJX == 312-112){return true;} else {return false;}" fullword ascii
    $s18 = "function UXEJ(cyDJX) {" fullword ascii
    $s19 = "function GxqpnpW(ZIfa) {" fullword ascii
    $s20 = "return BhzGY;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}