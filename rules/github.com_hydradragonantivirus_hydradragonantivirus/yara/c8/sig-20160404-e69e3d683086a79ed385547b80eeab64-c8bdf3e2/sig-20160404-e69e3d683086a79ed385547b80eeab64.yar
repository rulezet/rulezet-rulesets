rule sig_20160404_e69e3d683086a79ed385547b80eeab64 {
  meta:
    description = "datamaliciousorder - file 20160404_e69e3d683086a79ed385547b80eeab64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db6a344e783e1f1a0152b4c8d24e41e582fae35340711a4de7a0b88794b7243"

  strings:
    $s1  = "var vF = true  , nFXm = XaQ[7] + XaQ[9] + XaQ[11];" fullword ascii
    $s2  = "return GhCFxYu[0] + GhCFxYu[2] + GhCFxYu[4] + \".F\" + GhCFxYu[7] + GhCFxYu[9] + GhCFxYu[12] + GhCFxYu[14];" fullword ascii
    $s3  = "nJiX.open(orEny,azhnR,false);" fullword ascii
    $s4  = "var XaQ = (\"2.XMLHTTP qxoZacD GwUba XML ream St BHYmikpR AD CrnlMCH O ysQQ D\").split(\" \");" fullword ascii
    $s5  = "var GhCFxYu = ZJLYx(yVRPXxwgcb+\" \"+\"System NF Irgfz Obj uOdqyX ect spxuMGw ZxlId\", \" \");" fullword ascii
    $s6  = "return gSq.split(UdYrv);" fullword ascii
    $s7  = "function maAh(rxJME,RFQRA) {" fullword ascii
    $s8  = "return eommF;" fullword ascii
    $s9  = "if (JIcOc > 186821-820){return true;} else {return false;}" fullword ascii
    $s10 = "function NqRdq(pKbttR) {" fullword ascii
    $s11 = "function qUOdosMc(pSp) {" fullword ascii
    $s12 = "function WWvnXC(kTka,soBQPD) {" fullword ascii
    $s13 = "return WabNINs;" fullword ascii
    $s14 = "function dvTT(lyzyZ) {" fullword ascii
    $s15 = "function YHEu(JIcOc) {" fullword ascii
    $s16 = "return \"birdXeYROHMjvx\";" fullword ascii
    $s17 = "if(s>=S.length) {break;}" fullword ascii
    $s18 = "function KvNWhJ(aCLowVQ) {" fullword ascii
    $s19 = "return sNAiExe;" fullword ascii
    $s20 = "function rwFdggAPu(EmoIl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}