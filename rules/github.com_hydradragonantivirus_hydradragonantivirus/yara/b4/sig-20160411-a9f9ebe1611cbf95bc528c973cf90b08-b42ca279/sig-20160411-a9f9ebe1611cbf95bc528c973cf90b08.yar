rule sig_20160411_a9f9ebe1611cbf95bc528c973cf90b08 {
  meta:
    description = "datamaliciousorder - file 20160411_a9f9ebe1611cbf95bc528c973cf90b08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b81667090a65656c16dd9d470da8a0b544f1a877784cd85dbc3a7d80f3a3cfc"

  strings:
    $s1  = "var Kj = true  , Prqa = Qay[7] + Qay[9] + Qay[11];" fullword ascii
    $s2  = "return hfybOHj[0] + hfybOHj[2] + hfybOHj[4] + \".F\" + hfybOHj[7] + hfybOHj[9] + hfybOHj[12] + hfybOHj[14];" fullword ascii
    $s3  = "var Qay = (\"2.XMLHTTP KDKsbGq ntuXZ XML ream St yshTnhSX AD xRPDDoF O Rfrq D\").split(\" \");" fullword ascii
    $s4  = "function wjGuF(whfubRoT,ucMD) {" fullword ascii
    $s5  = "AIRr.open(ZQvKo,bKnFK,false);" fullword ascii
    $s6  = "if(I>=l.length) {break;}" fullword ascii
    $s7  = "function doyP(vBLJi,mVayr) {" fullword ascii
    $s8  = "return Wxyp[nIlmEgU[0]+nIlmEgU[1]];" fullword ascii
    $s9  = "function eYbtw(yMuBGl) {" fullword ascii
    $s10 = "function IZxDziF(Wxyp) {" fullword ascii
    $s11 = "function biJZ(nNtLH) {" fullword ascii
    $s12 = "function szPR(ZBchi) {" fullword ascii
    $s13 = "function JRNyszxJ(tMuw) {" fullword ascii
    $s14 = "if (y >= CsGWz.length) {break;}" fullword ascii
    $s15 = "function TZmHZUUqA(iljDY) {" fullword ascii
    $s16 = "function ANNdbAzi(kWN) {" fullword ascii
    $s17 = "return Dwz[oPeZ[0]](mZbOs);" fullword ascii
    $s18 = "return kWN.size;" fullword ascii
    $s19 = "return WxzRqZr(nq,cjHAPA+Zffbn[388-380]);" fullword ascii
    $s20 = "return HAPEJ.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}