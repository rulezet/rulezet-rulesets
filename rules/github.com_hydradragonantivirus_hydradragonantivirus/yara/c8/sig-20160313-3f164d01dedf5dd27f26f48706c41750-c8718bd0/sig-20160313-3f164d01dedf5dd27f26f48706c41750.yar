rule sig_20160313_3f164d01dedf5dd27f26f48706c41750 {
  meta:
    description = "datamaliciousorder - file 20160313_3f164d01dedf5dd27f26f48706c41750.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85740bb87992b1bac77a2b5e740406b170520380a88032c69bdaaa4512c3975a"

  strings:
    $s1  = "return KFuvqOg[0] + KFuvqOg[2] + KFuvqOg[4] + \".F\" + KFuvqOg[7] + KFuvqOg[9] + KFuvqOg[12] + KFuvqOg[14];" fullword ascii
    $s2  = "var YG = true  , zbQc = lgA[7] + lgA[9] + lgA[11];" fullword ascii
    $s3  = "var lgA = (\"2.XMLHTTP sdopNlA xZdcv XML ream St itUOWebE AD EIDGfCy O ETIh D\").split(\" \");" fullword ascii
    $s4  = "XnAoH.open(miMtQ,kWTrI,false);" fullword ascii
    $s5  = "var KFuvqOg = \"Sc gkrxyRv r rQKAIkSJL ipting FCWaZZP zNz ile wDdnQBqnHZvwRK System dn PvwqS Obj uTVDNK ect lHLWPbN\".split(\" " ascii
    $s6  = "if(e>=A.length) {break;}" fullword ascii
    $s7  = "return drxfnLB" fullword ascii
    $s8  = "return ipD.size;" fullword ascii
    $s9  = "if (BjPir == 331-131){return true;} else {return false;}" fullword ascii
    $s10 = "function SeOV(ZGXdi) {" fullword ascii
    $s11 = "return new ActiveXObject(mPKEFx);" fullword ascii
    $s12 = "function qYla(cegcg) {" fullword ascii
    $s13 = "function WYueQLPoI() {" fullword ascii
    $s14 = "return gMvg.ExpandEnvironmentStrings(pHsGi);" fullword ascii
    $s15 = "if (B >= eCeQR.length) {break;}" fullword ascii
    $s16 = "function dKEnJLtx(ipD) {" fullword ascii
    $s17 = "function URxN(BjPir) {" fullword ascii
    $s18 = "function XQPR(eCeQR) {" fullword ascii
    $s19 = "return jUmuMWB(xN,mwvYW[534-528]+mwvYW[998-991]+mwvYW[913-905]);" fullword ascii
    $s20 = "function jxCFctt(aInO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}