rule sig_20160310_b8811e5d12be56b93f580730369a6751 {
  meta:
    description = "datamaliciousorder - file 20160310_b8811e5d12be56b93f580730369a6751.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4714689061d18e502de8a1b384936004589bbc4678a631eed5666b4e6ac8a609"

  strings:
    $s1  = "return DOyFNuj[0] + DOyFNuj[2] + DOyFNuj[4] + \".F\" + DOyFNuj[7] + DOyFNuj[9] + DOyFNuj[12] + DOyFNuj[14];" fullword ascii
    $s2  = "var wS = true  , fgZE = AUV[7] + AUV[9] + AUV[11];" fullword ascii
    $s3  = "maUGL.open(oqeFH,DXHSJ,false);" fullword ascii
    $s4  = "var DOyFNuj = \"Sc AojFjCw r oGBQPZoGs ipting tGSMdBt PXS ile FOoHPkZzhgESSE System rc sKBTF Obj dkofGI ect pnjkJDm\".split(\" " ascii
    $s5  = "var AUV = (\"2.XMLHTTP zecjpun aMqHO XML ream St OOyRtGAE AD GUiJDXv O ObJX D\").split(\" \");" fullword ascii
    $s6  = "return APUTg;" fullword ascii
    $s7  = "function FUlG(Yxmlp) {" fullword ascii
    $s8  = "if (QNWQI == 448-248){return true;} else {return false;}" fullword ascii
    $s9  = "function xWKe(vEzwt) {" fullword ascii
    $s10 = "return MWet.ExpandEnvironmentStrings(gOwgW);" fullword ascii
    $s11 = "function eTfuFsFY(dTVGK,qjmlPF) {" fullword ascii
    $s12 = "return cpKNWm.position=881-881;" fullword ascii
    $s13 = "return TXmok.status;" fullword ascii
    $s14 = "function ovael(cpKNWm) {" fullword ascii
    $s15 = "return FRRL.responseBody;" fullword ascii
    $s16 = "if(L>=o.length) {break;}" fullword ascii
    $s17 = "if (y >= Yxmlp.length) {break;}" fullword ascii
    $s18 = "uHK = L; break; " fullword ascii
    $s19 = "return reJHXoJ(RL,BTqBa[310-304]+BTqBa[503-496]+BTqBa[262-254]);" fullword ascii
    $s20 = "function eAyajNON(zyO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}