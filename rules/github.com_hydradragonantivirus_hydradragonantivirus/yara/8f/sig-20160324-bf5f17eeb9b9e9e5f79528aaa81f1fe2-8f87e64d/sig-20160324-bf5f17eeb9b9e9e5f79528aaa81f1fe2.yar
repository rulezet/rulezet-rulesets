rule sig_20160324_bf5f17eeb9b9e9e5f79528aaa81f1fe2 {
  meta:
    description = "datamaliciousorder - file 20160324_bf5f17eeb9b9e9e5f79528aaa81f1fe2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be53795354eb563ba1f105ccd5a367481b6051e7ed200a22559fb5adb284b9db"

  strings:
    $s1  = "return WScript.CreateObject(YIjgu);" fullword ascii
    $s2  = "var Oj = true  , aCoz = elc[7] + elc[9] + elc[11];" fullword ascii
    $s3  = "return sFknbQd[0] + sFknbQd[2] + sFknbQd[4] + \".F\" + sFknbQd[7] + sFknbQd[9] + sFknbQd[12] + sFknbQd[14];" fullword ascii
    $s4  = "var elc = (\"2.XMLHTTP NDcCOFE GhJEH XML ream St vIyokEHz AD DXXoscn O eKOX D\").split(\" \");" fullword ascii
    $s5  = "var sFknbQd = sjaiG(qyaSdwixTc+\" \"+\"System uw QocBL Obj NLGTIe ect JRiOaTK hTqjt\", \" \");" fullword ascii
    $s6  = "lnru.open(hIkKk,chYTl,false);" fullword ascii
    $s7  = "function aYdF(YSQeE) {" fullword ascii
    $s8  = "function cxil(SQoFy,chYTl,hIkKk) {" fullword ascii
    $s9  = "function RCMR(ufmgR,cErPD) {" fullword ascii
    $s10 = "function GxXY(CJSEo) {" fullword ascii
    $s11 = "return IrLStf/*OHqjKFNUQ3av0RtFTNBwNhw2h*/.position=596-596;" fullword ascii
    $s12 = "return zmZriKc(JI,TWMkr[384-378]+TWMkr[424-417]+TWMkr[679-671]);" fullword ascii
    $s13 = "function iZmD(YIjgu) {" fullword ascii
    $s14 = "return new ActiveXObject(Tpxk);" fullword ascii
    $s15 = "return DxkKI;" fullword ascii
    $s16 = "function ALTzQ(HhGlbefQ,apPS) {" fullword ascii
    $s17 = "function OWWu(EUcdg) {" fullword ascii
    $s18 = "function EOwY(dquhf) {" fullword ascii
    $s19 = "function zmZriKc(KmTA,yWtKZ) {" fullword ascii
    $s20 = "function UPgYzPbXp(wukiGgJsidq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}