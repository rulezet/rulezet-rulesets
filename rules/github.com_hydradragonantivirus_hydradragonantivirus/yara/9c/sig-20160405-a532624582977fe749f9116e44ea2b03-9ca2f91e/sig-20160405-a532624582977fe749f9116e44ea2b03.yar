rule sig_20160405_a532624582977fe749f9116e44ea2b03 {
  meta:
    description = "datamaliciousorder - file 20160405_a532624582977fe749f9116e44ea2b03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59ffce8846c474791891149ee621fd4ff91adb2c4f3a0fff8188106d9e37c590"

  strings:
    $s1  = "function dtFT(GETHp) {" fullword ascii
    $s2  = "if (o >= GETHp.length) {break;}" fullword ascii
    $s3  = "var cp = true  , dTIz = Iol[7] + Iol[9] + Iol[11];" fullword ascii
    $s4  = "return sbvKoyN[0] + sbvKoyN[2] + sbvKoyN[4] + \".F\" + sbvKoyN[7] + sbvKoyN[9] + sbvKoyN[12] + sbvKoyN[14];" fullword ascii
    $s5  = "RVWF.open(BTunF,sFTqk,false);" fullword ascii
    $s6  = "var Iol = (\"2.XMLHTTP eUtasGN dfzfK XML ream St XhmeXiGd AD qjkOmqL O MiQT D\").split(\" \");" fullword ascii
    $s7  = "function oQKhsWFMX(McTnt) {" fullword ascii
    $s8  = "function ieMhgZrc(ChPN) {" fullword ascii
    $s9  = "return kYDEsyv[0];" fullword ascii
    $s10 = "function etVp(Tawhe) {" fullword ascii
    $s11 = "function xeHD(vwmSA,RTwqP) {" fullword ascii
    $s12 = "function gjTWMNRz(HPQ) {" fullword ascii
    $s13 = "return oLdzSdm(Te,ONerx[518-512]+ONerx[124-117]+ONerx[866-858]);" fullword ascii
    $s14 = "if (eFKRy > 194522-754){return true;} else {return false;}" fullword ascii
    $s15 = "return Fnlm;" fullword ascii
    $s16 = "function GFkvLHFte(supwkZToTSI) {" fullword ascii
    $s17 = "return uzehr;" fullword ascii
    $s18 = "function Qfqi(AyXEq,sFTqk,BTunF) {" fullword ascii
    $s19 = "return JZmE[GHwrpJ[0]];" fullword ascii
    $s20 = "gJQ = j; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}