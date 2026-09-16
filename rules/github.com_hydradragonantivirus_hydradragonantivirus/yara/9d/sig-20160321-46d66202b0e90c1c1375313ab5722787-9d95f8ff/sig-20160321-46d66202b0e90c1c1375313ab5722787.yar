rule sig_20160321_46d66202b0e90c1c1375313ab5722787 {
  meta:
    description = "datamaliciousorder - file 20160321_46d66202b0e90c1c1375313ab5722787.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c82fef0c2591378f1fbca4ab7ad6f13fea81a9e3a39518362416ae05e4a4b9f"

  strings:
    $s1  = "return WScript.CreateObject(KaJRD);" fullword ascii
    $s2  = "return JBiUSkg[0] + JBiUSkg[2] + JBiUSkg[4] + \".F\" + JBiUSkg[7] + JBiUSkg[9] + JBiUSkg[12] + JBiUSkg[14];" fullword ascii
    $s3  = "var PB = true  , CFAD = nfL[7] + nfL[9] + nfL[11];" fullword ascii
    $s4  = "var nfL = (\"2.XMLHTTP CQSLkUW qBOhS XML ream St lbssfrCB AD oOLQEgB O keMu D\").split(\" \");" fullword ascii
    $s5  = "var JBiUSkg = viZNF(WJCmVZaflJ+\" \"+\"System qS PmXQp Obj JspLUu ect uuxFVXI pPxwX\", \" \");" fullword ascii
    $s6  = "UzOXZ.open(UOAkb,UgTcO,false);" fullword ascii
    $s7  = "if (q >= Wpdoj.length) {break;}" fullword ascii
    $s8  = "if (OQZei > 162388-888){return true;} else {return false;}" fullword ascii
    $s9  = "return Wzfee;" fullword ascii
    $s10 = "function iGKB(qlUQr) {" fullword ascii
    $s11 = "return PMzmffT(hJ,CglDV[348-342]+CglDV[113-106]+CglDV[698-690]);" fullword ascii
    $s12 = "if(t>=Y.length) {break;}" fullword ascii
    $s13 = "function jRPze(DmDMEb) {" fullword ascii
    $s14 = "function PMzmffT(crVG,oeDrj) {" fullword ascii
    $s15 = "function VxSA(KaJRD) {" fullword ascii
    $s16 = "function lTMW(OQZei) {" fullword ascii
    $s17 = "function vQTt(DoMEM) {" fullword ascii
    $s18 = "function hMyJKDbyf(mpmhLEzHJdb) {" fullword ascii
    $s19 = "return crVG.ExpandEnvironmentStrings(oeDrj);" fullword ascii
    $s20 = "return qAYS[PIfLGp[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}