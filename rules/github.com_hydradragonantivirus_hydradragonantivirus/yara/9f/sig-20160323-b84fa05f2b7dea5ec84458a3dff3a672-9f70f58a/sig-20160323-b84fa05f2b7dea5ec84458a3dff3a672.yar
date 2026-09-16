rule sig_20160323_b84fa05f2b7dea5ec84458a3dff3a672 {
  meta:
    description = "datamaliciousorder - file 20160323_b84fa05f2b7dea5ec84458a3dff3a672.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af80120ff0f831adae210ae86f134432e3a3b57aecbe4f3b992b7eefd9bbf50a"

  strings:
    $s1  = "return WScript.CreateObject(AMwTv);" fullword ascii
    $s2  = "var zs = true  , lgGG = TDL[7] + TDL[9] + TDL[11];" fullword ascii
    $s3  = "return YSwQnIi[0] + YSwQnIi[2] + YSwQnIi[4] + \".F\" + YSwQnIi[7] + YSwQnIi[9] + YSwQnIi[12] + YSwQnIi[14];" fullword ascii
    $s4  = "var YSwQnIi = TxXuY(tFOPluvZiG+\" \"+\"System RZ DtSNt Obj OHTlit ect Whsmlyl ApRIJ\", \" \");" fullword ascii
    $s5  = "var TDL = (\"2.XMLHTTP zgqqqOn WWyQQ XML ream St tqlMFdlA AD OhfTWbp O kLRC D\").split(\" \");" fullword ascii
    $s6  = "lrba.open(wLYJy,cZczh,false);" fullword ascii
    $s7  = "function Zclc(NgeIZ) {" fullword ascii
    $s8  = "Xyl = E; break; " fullword ascii
    $s9  = "function HyQwI(PiPwjr) {" fullword ascii
    $s10 = "return Gumyt.status;" fullword ascii
    $s11 = "function ERwDdCJp(ARcu) {" fullword ascii
    $s12 = "function qEOe(nLvXx) {" fullword ascii
    $s13 = "return bsKO.ExpandEnvironmentStrings(KJxHX);" fullword ascii
    $s14 = "function KXuMCLG(BGAr) {" fullword ascii
    $s15 = "return new ActiveXObject(TZoq);" fullword ascii
    $s16 = "return LiEglfF(SE,gSSAv[910-904]+gSSAv[910-903]+gSSAv[437-429]);" fullword ascii
    $s17 = "if (NgeIZ == 657-457){return true;} else {return false;}" fullword ascii
    $s18 = "function GkrG(qnTMy,rXevC) {" fullword ascii
    $s19 = "function TxXuY(ffB,GWxgt) {" fullword ascii
    $s20 = "function bmxE(Gumyt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}