rule sig_20160324_4edf3fbc01f6b00185694bccb0a2d62b {
  meta:
    description = "datamaliciousorder - file 20160324_4edf3fbc01f6b00185694bccb0a2d62b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a4bb8c0e86956c2a01341ef7b4f8024d11b73928ec2a7e7ce5afaad8a671034"

  strings:
    $s1  = "return WScript.CreateObject(TqECc);" fullword ascii
    $s2  = "return KcobjZb[0] + KcobjZb[2] + KcobjZb[4] + \".F\" + KcobjZb[7] + KcobjZb[9] + KcobjZb[12] + KcobjZb[14];" fullword ascii
    $s3  = "var Mb = true  , RTOw = gKn[7] + gKn[9] + gKn[11];" fullword ascii
    $s4  = "var KcobjZb = pbeeg(fONlbvnaxY+\" \"+\"System Bm KMpaU Obj jMKaSq ect ymlPoFu SdHVU\", \" \");" fullword ascii
    $s5  = "RrWI.open(aciIr,eTESD,false);" fullword ascii
    $s6  = "var gKn = (\"2.XMLHTTP XWtEPHS VFJsa XML ream St mKpXfrVb AD KrzkXaI O Guzn D\").split(\" \");" fullword ascii
    $s7  = "return BqN.split(jTRoa);" fullword ascii
    $s8  = "return oHLMe.status;" fullword ascii
    $s9  = "function FcMA(otNEF) {" fullword ascii
    $s10 = "function rSWe(XAPrX,tVFcp) {" fullword ascii
    $s11 = "return GFufytV(PA,dTkzL[804-798]+dTkzL[461-454]+dTkzL[319-311]);" fullword ascii
    $s12 = "return swoS[rhOKPA[0]];" fullword ascii
    $s13 = "function VshmR(UiDnyT) {" fullword ascii
    $s14 = "function jprzA(BkNEvd) {" fullword ascii
    $s15 = "function eSYK(fnDGq) {" fullword ascii
    $s16 = "if (z >= PNSOl.length) {break;}" fullword ascii
    $s17 = "function qDCYhoNzw(RIMuD) {" fullword ascii
    $s18 = "function xnOR(eXuJm,eTESD,aciIr) {" fullword ascii
    $s19 = "return new ActiveXObject(umiM);" fullword ascii
    $s20 = "UMr = M; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}