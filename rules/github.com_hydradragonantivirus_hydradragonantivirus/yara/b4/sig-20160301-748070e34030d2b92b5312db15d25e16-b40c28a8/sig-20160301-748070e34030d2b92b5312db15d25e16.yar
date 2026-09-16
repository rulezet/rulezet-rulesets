rule sig_20160301_748070e34030d2b92b5312db15d25e16 {
  meta:
    description = "datamaliciousorder - file 20160301_748070e34030d2b92b5312db15d25e16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac04e7277c9553464fda1e84e0b7cfcf88efbabce056be380f5b5f025e3d72bb"

  strings:
    $s1  = "var vK = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(rWYeD);" fullword ascii
    $s3  = "var nO = true  , EKzY = alQ[7] + \"\" + alQ[9];" fullword ascii
    $s4  = "var alQ = (zOp + \"TTP\" + \" qMsLYJo qidsD XML ream St UkDJaJRT AD dRgeqTU OD\").split(\" \");" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + rfqGcJP + \".F\" + vTuyUpBMrq + gTvcS + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "pwUCT.open(fYkzd,oTpWh,false);" fullword ascii
    $s7  = "function UtakFRtcC(JtEVWPpiarX) {" fullword ascii
    $s8  = "if (Vcvut == 560-360){return true;} else {return false;}" fullword ascii
    $s9  = "function COFc(rWYeD) {" fullword ascii
    $s10 = "return new ActiveXObject(DnQjNS);" fullword ascii
    $s11 = "function wAAq(qibat) {" fullword ascii
    $s12 = "function fBwy(Vcvut) {" fullword ascii
    $s13 = "return jl.ExpandEnvironmentStrings(vK);" fullword ascii
    $s14 = "function IMuO(gtauI) {" fullword ascii
    $s15 = "function AKiy(thkcU) {" fullword ascii
    $s16 = "function nAMM(pwUCT,oTpWh,fYkzd) {" fullword ascii
    $s17 = "function TOYVkwqcc(cRPvB,KPtiF,yXTEU) {" fullword ascii
    $s18 = "function ZKAo(GksGc,gqafD) {" fullword ascii
    $s19 = "asP = G; break; " fullword ascii
    $s20 = "return AglGh.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}