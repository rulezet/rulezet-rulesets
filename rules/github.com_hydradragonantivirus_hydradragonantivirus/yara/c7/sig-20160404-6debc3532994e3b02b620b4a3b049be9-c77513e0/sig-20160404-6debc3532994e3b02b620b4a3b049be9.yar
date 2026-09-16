rule sig_20160404_6debc3532994e3b02b620b4a3b049be9 {
  meta:
    description = "datamaliciousorder - file 20160404_6debc3532994e3b02b620b4a3b049be9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "546e7705e6326e9451a4c0c6bade3c9f46602d804e7dc8e86933329606e715b4"

  strings:
    $s1  = "return lEGkJvS[0] + lEGkJvS[2] + lEGkJvS[4] + \".F\" + lEGkJvS[7] + lEGkJvS[9] + lEGkJvS[12] + lEGkJvS[14];" fullword ascii
    $s2  = "var HU = true  , XaGi = efH[7] + efH[9] + efH[11];" fullword ascii
    $s3  = "var lEGkJvS = QeLps(pUjcgUVphu+\" \"+\"System HT arexQ Obj mimDSy ect NEEbowF yyavF\", \" \");" fullword ascii
    $s4  = "yxfx.open(RSaqv,kdXLj,false);" fullword ascii
    $s5  = "var efH = (\"2.XMLHTTP kuQCFDu QcEEk XML ream St KhveEktd AD bKoEEgN O GnLP D\").split(\" \");" fullword ascii
    $s6  = "function mJlr(yfmOz) {" fullword ascii
    $s7  = "return new ActiveXObject(hdGD);" fullword ascii
    $s8  = "if (o >= yfmOz.length) {break;}" fullword ascii
    $s9  = "return KkYqy.status;" fullword ascii
    $s10 = "function suMSiiY(KXaT,heCxL) {" fullword ascii
    $s11 = "function RLIRKZHvQ(ZhICcxMVTyg) {" fullword ascii
    $s12 = "return PBep[TyBMOI[0]];" fullword ascii
    $s13 = "function fUGy(PbLPo) {" fullword ascii
    $s14 = "function JdsJ(KkYqy) {" fullword ascii
    $s15 = "var ECjoILP = \"FjEkOJ*YVw*pt.S\"+\"hell*RpPwEXM*Scri*\";" fullword ascii
    $s16 = "function MYsq(CCEHC) {" fullword ascii
    $s17 = "function dKzs(JNpir,qkFcQ) {" fullword ascii
    $s18 = "function iAtLDzr(PBep) {" fullword ascii
    $s19 = "function tafMGx(yITdKvh) {" fullword ascii
    $s20 = "return suMSiiY(Pk,iYSJY[196-190]+iYSJY[866-859]+iYSJY[253-245]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}