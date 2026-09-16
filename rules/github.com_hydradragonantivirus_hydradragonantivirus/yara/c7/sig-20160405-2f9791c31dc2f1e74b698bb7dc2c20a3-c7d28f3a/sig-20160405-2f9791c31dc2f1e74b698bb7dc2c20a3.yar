rule sig_20160405_2f9791c31dc2f1e74b698bb7dc2c20a3 {
  meta:
    description = "datamaliciousorder - file 20160405_2f9791c31dc2f1e74b698bb7dc2c20a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d67aee37cd602e6945da829fb85a683e9d7e8aaeb4b1cae35420da2ece84b187"

  strings:
    $s1  = "var Mv = true  , jAlL = hgY[7] + hgY[9] + hgY[11];" fullword ascii
    $s2  = "return LlBobhU[0] + LlBobhU[2] + LlBobhU[4] + \".F\" + LlBobhU[7] + LlBobhU[9] + LlBobhU[12] + LlBobhU[14];" fullword ascii
    $s3  = "OfGi.open(qWchm,LOBML,false);" fullword ascii
    $s4  = "var hgY = (\"2.XMLHTTP FXtOgpP ETaqN XML ream St mmXoAQxv AD NqAIkwv O CYtg D\").split(\" \");" fullword ascii
    $s5  = "if(B>=l.length) {break;}" fullword ascii
    $s6  = "function iyUOBfnE(qlWD) {" fullword ascii
    $s7  = "return OXlRRuj;" fullword ascii
    $s8  = "return LUfi;" fullword ascii
    $s9  = "return dFuMgzj[0];" fullword ascii
    $s10 = "return new ActiveXObject(SYhO);" fullword ascii
    $s11 = "function YYWlSAoe(Zao) {" fullword ascii
    $s12 = "function wogh(QQAtz,LOBML,qWchm) {" fullword ascii
    $s13 = "function XySg(PyHkR) {" fullword ascii
    $s14 = "function nTGe(FGsVU) {" fullword ascii
    $s15 = "function PMLCU(JaPsPM) {" fullword ascii
    $s16 = "function JHDgTFxtO(aXFoO) {" fullword ascii
    $s17 = "function EgREHto(kzSd,lVopt) {" fullword ascii
    $s18 = "function tuYOE(KKhDuo) {" fullword ascii
    $s19 = "return Zao.size;" fullword ascii
    $s20 = "if (SFmAU == 804-604){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}