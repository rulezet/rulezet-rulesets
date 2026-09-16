rule sig_20160227_11d4ce7bcea66cb52ce19faf0cb772e7 {
  meta:
    description = "datamaliciousorder - file 20160227_11d4ce7bcea66cb52ce19faf0cb772e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31b86913f42def44468a968e6fa29e1c1a6be90ad6ad6fd9bbf8261dc314392f"

  strings:
    $s1  = "var Mm = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(xoAMA);" fullword ascii
    $s3  = "var OR = true  , jjLM = \"AD\" + \"\" + \"OD\";" fullword ascii
    $s4  = "var rqY = (IAy + \"TTP\" + \" tUjUlQM fikaK XML ream St\").split(\" \");" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + CMFRwHV + \".F\" + ZUVRAESFkg + dWhVM + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "KPImC.open(FqBCT,xPFrO,false);" fullword ascii
    $s7  = "function eJvZyyDrn(LnISm,WLTTl,HTIpw) {" fullword ascii
    $s8  = "return aU.ExpandEnvironmentStrings(Mm);" fullword ascii
    $s9  = "function ZCHT(KPImC,xPFrO,FqBCT) {" fullword ascii
    $s10 = "function iVQp(xoAMA) {" fullword ascii
    $s11 = "function AXcI(UVGiS,stxXf) {" fullword ascii
    $s12 = "function OvzWshbV() {" fullword ascii
    $s13 = "LiI = m; break; " fullword ascii
    $s14 = "if (ZgICj > 171550-196){return true;} else {return false;}" fullword ascii
    $s15 = "function VoEj(gDKXD,OXMUg) {" fullword ascii
    $s16 = "function lqvN(ZgICj) {" fullword ascii
    $s17 = "return gTRbI;" fullword ascii
    $s18 = "if (kIocD == 558-358){return true;} else {return false;}" fullword ascii
    $s19 = "function bluwxaYCf(RXIONwJifDU) {" fullword ascii
    $s20 = "if(m>=T.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}