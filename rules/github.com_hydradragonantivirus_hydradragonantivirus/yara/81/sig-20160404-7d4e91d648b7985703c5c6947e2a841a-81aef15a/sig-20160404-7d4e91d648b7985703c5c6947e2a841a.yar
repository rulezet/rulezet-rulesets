rule sig_20160404_7d4e91d648b7985703c5c6947e2a841a {
  meta:
    description = "datamaliciousorder - file 20160404_7d4e91d648b7985703c5c6947e2a841a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68016f6aed69568b23efe82af8fcc74f3587b7a358786be13627625de53988db"

  strings:
    $s1  = "return ESfHaQI[0] + ESfHaQI[2] + ESfHaQI[4] + \".F\" + ESfHaQI[7] + ESfHaQI[9] + ESfHaQI[12] + ESfHaQI[14];" fullword ascii
    $s2  = "var ql = true  , Aeyl = goa[7] + goa[9] + goa[11];" fullword ascii
    $s3  = "var goa = (\"2.XMLHTTP kvcWMdi ihYJq XML ream St xjvFHlYa AD CZkZEVU O AiRe D\").split(\" \");" fullword ascii
    $s4  = "var ESfHaQI = zIhXy(mLiqBLKSxV+\" \"+\"System Qi jeFqW Obj JNYrJE ect KsrArPS rLdXN\", \" \");" fullword ascii
    $s5  = "rpLM.open(kGoyR,gCQgg,false);" fullword ascii
    $s6  = "function hTtp(ffRWY,gCQgg,kGoyR) {" fullword ascii
    $s7  = "if(Z>=U.length) {break;}" fullword ascii
    $s8  = "if (K >= GuRAB.length) {break;}" fullword ascii
    $s9  = "function NBqt(oRBmJ,qMrRw) {" fullword ascii
    $s10 = "return feHooRt;" fullword ascii
    $s11 = "tEq = Z; break; " fullword ascii
    $s12 = "function GdMI(GuRAB) {" fullword ascii
    $s13 = "function zIhXy(GjF,PqNfH) {" fullword ascii
    $s14 = "function YTze(ZHYDc) {" fullword ascii
    $s15 = "function wCMh(CmIIm) {" fullword ascii
    $s16 = "return XEBn[uEiAfz[0]];" fullword ascii
    $s17 = "if (NfUqF == 808-608){return true;} else {return false;}" fullword ascii
    $s18 = "function oJKvjspP(BIY) {" fullword ascii
    $s19 = "function RcEP(NfUqF) {" fullword ascii
    $s20 = "function OwpP(NLgfQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}