rule sig_20160405_87a797278c69cf525ed0cc02676fe3a7 {
  meta:
    description = "datamaliciousorder - file 20160405_87a797278c69cf525ed0cc02676fe3a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0818a4e5d57267032a10fce21c6dc8b00d23154f9ef261763d92318d0e048665"

  strings:
    $s1  = "return KnMcZQg[0] + KnMcZQg[2] + KnMcZQg[4] + \".F\" + KnMcZQg[7] + KnMcZQg[9] + KnMcZQg[12] + KnMcZQg[14];" fullword ascii
    $s2  = "var qo = true  , ssEd = FQY[7] + FQY[9] + FQY[11];" fullword ascii
    $s3  = "var ZeV = (\"ht\" + \" NUnlzbn tp BeseE BtaODYNk :// INKCGlC .e RzmNM x RiKIrK e G TKlRlwg E wRuAiXKk T GLoD\").split(\" \");" fullword ascii
    $s4  = "Vvzi.open(Uzanu,tJgwP,false);" fullword ascii
    $s5  = "function bBTFCxsU(QcbI) {" fullword ascii
    $s6  = "return iTS.size;" fullword ascii
    $s7  = "function FLcuAWq(fdeZ,MnzOF) {" fullword ascii
    $s8  = "function ZtHO(CbGXn) {" fullword ascii
    $s9  = "return uvDWBFw;" fullword ascii
    $s10 = "function Trfq(IqUyu) {" fullword ascii
    $s11 = "return sKv.split(zPiro);" fullword ascii
    $s12 = "function ZtPbUn(QZVujwr) {" fullword ascii
    $s13 = "function mEoD(ymDYn) {" fullword ascii
    $s14 = "function fdDxGqX(CLsp) {" fullword ascii
    $s15 = "function qGke(GLkjs) {" fullword ascii
    $s16 = "function iGabq(cYUnCB) {" fullword ascii
    $s17 = "function xRMqIjgDy(DUGql) {" fullword ascii
    $s18 = "if (t >= ymDYn.length) {break;}" fullword ascii
    $s19 = "return nLVej.status;" fullword ascii
    $s20 = "return JJSvh;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}