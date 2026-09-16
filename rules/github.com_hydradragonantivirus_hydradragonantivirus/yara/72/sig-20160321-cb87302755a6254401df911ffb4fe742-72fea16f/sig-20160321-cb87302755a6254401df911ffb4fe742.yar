rule sig_20160321_cb87302755a6254401df911ffb4fe742 {
  meta:
    description = "datamaliciousorder - file 20160321_cb87302755a6254401df911ffb4fe742.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362d6ea6640982adbdad6a23934c08593fdd6775df6ab77b8e2d7143ed3f6a13"

  strings:
    $s1  = "return WScript.CreateObject(VPcpZ);" fullword ascii
    $s2  = "return EsVqsPu[0] + EsVqsPu[2] + EsVqsPu[4] + \".F\" + EsVqsPu[7] + EsVqsPu[9] + EsVqsPu[12] + EsVqsPu[14];" fullword ascii
    $s3  = "var eI = true  , Wsuh = DyA[7] + DyA[9] + DyA[11];" fullword ascii
    $s4  = "var EsVqsPu = amsgE(xtQrDRxLDB+\" \"+\"System nK OqSSi Obj GSmqMc ect nlVQEWa FnGxi\", \" \");" fullword ascii
    $s5  = "var DyA = (\"2.XMLHTTP RkHhmvz zxazP XML ream St pQDXZzOf AD tZhhJek O qdGu D\").split(\" \");" fullword ascii
    $s6  = "GpkpF.open(BvRsZ,xeKKE,false);" fullword ascii
    $s7  = "function amsgE(fNQ,kXXRd) {" fullword ascii
    $s8  = "return hkg.size;" fullword ascii
    $s9  = "return bFZLE.status;" fullword ascii
    $s10 = "function mZiU(NUaIB) {" fullword ascii
    $s11 = "if (a >= rihlz.length) {break;}" fullword ascii
    $s12 = "function QqVsgvyX(PlqG) {" fullword ascii
    $s13 = "function LIpy(PEmQu,lQjRq) {" fullword ascii
    $s14 = "if (yCeNK > 175264-794){return true;} else {return false;}" fullword ascii
    $s15 = "function iNECmfc(IhFq) {" fullword ascii
    $s16 = "function LDuyd(WhlaIP) {" fullword ascii
    $s17 = "function KKZawBpbH(etNsiLoSTAr) {" fullword ascii
    $s18 = "function OtRP(VPcpZ) {" fullword ascii
    $s19 = "return VaQkG;" fullword ascii
    $s20 = "function olti(Uomgb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}