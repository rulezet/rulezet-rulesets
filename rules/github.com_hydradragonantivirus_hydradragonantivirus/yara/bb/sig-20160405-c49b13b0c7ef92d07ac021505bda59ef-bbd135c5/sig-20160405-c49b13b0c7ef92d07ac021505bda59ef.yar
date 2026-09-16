rule sig_20160405_c49b13b0c7ef92d07ac021505bda59ef {
  meta:
    description = "datamaliciousorder - file 20160405_c49b13b0c7ef92d07ac021505bda59ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdb47e16272c55f785b1bece8097f4240d3f559719acaf0feb326afa5848e58a"

  strings:
    $s1  = "return IoWimmt[0] + IoWimmt[2] + IoWimmt[4] + \".F\" + IoWimmt[7] + IoWimmt[9] + IoWimmt[12] + IoWimmt[14];" fullword ascii
    $s2  = "var AN = true  , pGSI = iKO[7] + iKO[9] + iKO[11];" fullword ascii
    $s3  = "var iKO = (\"2.XMLHTTP JuQhouC SuEhQ XML ream St oJewHMEq AD MGbUTjX O PRoE D\").split(\" \");" fullword ascii
    $s4  = "hgyt.open(LaHup,tNSex,false);" fullword ascii
    $s5  = "return QYL.size;" fullword ascii
    $s6  = "return RpwiRWP(bL,BYqIR[878-872]+BYqIR[420-413]+BYqIR[230-222]);" fullword ascii
    $s7  = "function oOAQ(mRqJY) {" fullword ascii
    $s8  = "if (SBKsf == 707-507){return true;} else {return false;}" fullword ascii
    $s9  = "return UZvyr.status;" fullword ascii
    $s10 = "function LYxZ(YngRE) {" fullword ascii
    $s11 = "function nVRbecrO(Ozvk) {" fullword ascii
    $s12 = "return DRULJWj[0];" fullword ascii
    $s13 = "if(G>=V.length) {break;}" fullword ascii
    $s14 = "function UEVZFP(SXOIcSK) {" fullword ascii
    $s15 = "function xLNb(VYLgv) {" fullword ascii
    $s16 = "return ovqN;" fullword ascii
    $s17 = "function WcgdH(eHQGPjMo,RdOw) {" fullword ascii
    $s18 = "function KGiB(jriFJ,rQWqp) {" fullword ascii
    $s19 = "return aiUc[wzfTZr[0]];" fullword ascii
    $s20 = "if (YngRE > 165087-820){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}