rule sig_20160314_fbf9ec5cc9829202c41a4e9976396e8a {
  meta:
    description = "datamaliciousorder - file 20160314_fbf9ec5cc9829202c41a4e9976396e8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31591fd5c2c8ced7ad19ad73e21811d18a16950cd5020a13514c1bd7642dbd3"

  strings:
    $s1  = "ZBKsT.open(JICoM,OqqLc,false);" fullword ascii
    $s2  = "return leJQIRD[0] + leJQIRD[2] + leJQIRD[4] + \".F\" + leJQIRD[7] + leJQIRD[9] + leJQIRD[12] + leJQIRD[14];" fullword ascii
    $s3  = "var Qm = true  , zRbJ = daO[7] + daO[9] + daO[11];" fullword ascii
    $s4  = "var daO = (\"2.XMLHTTP GVvXynN FTCbG XML ream St LuTceKXr AD XRFMphq O DyBo D\").split(\" \");" fullword ascii
    $s5  = "var leJQIRD = \"Sc sQGRYHS r KOpIHbrvP ipting zedbEBx VTz ile dXEPptewDBijlL System rK DOzRZ Obj jvOJTK ect eyRdjSm ZhqzI\".spli" ascii
    $s6  = "var leJQIRD = \"Sc sQGRYHS r KOpIHbrvP ipting zedbEBx VTz ile dXEPptewDBijlL System rK DOzRZ Obj jvOJTK ect eyRdjSm ZhqzI\".spli" ascii
    $s7  = "function UogK(ZBKsT,OqqLc,JICoM) {" fullword ascii
    $s8  = "function xjnx(xPciR) {" fullword ascii
    $s9  = "if (l >= fGVsP.length) {break;}" fullword ascii
    $s10 = "if (rdOyb > 186967-775){return true;} else {return false;}" fullword ascii
    $s11 = "return EfMLuaj" fullword ascii
    $s12 = "function ffokHwY(vlhG,KmXNu) {" fullword ascii
    $s13 = "function foAWZLJ(QhsP) {" fullword ascii
    $s14 = "if (JIhLH == 728-528){return true;} else {return false;}" fullword ascii
    $s15 = "function QdYiJ(VacrUF) {" fullword ascii
    $s16 = "return QhsP.responseBody;" fullword ascii
    $s17 = "function eNcd(jByds) {" fullword ascii
    $s18 = "function BCXS(CpSKG) {" fullword ascii
    $s19 = "ZGn = p; break; " fullword ascii
    $s20 = "function USpA(fGVsP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}