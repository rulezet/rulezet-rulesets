rule sig_20160321_2fe51597ef890e77da9bcffc79e8c9d1 {
  meta:
    description = "datamaliciousorder - file 20160321_2fe51597ef890e77da9bcffc79e8c9d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f31cb7c5c39eb6a861916e7a3f72da2c4c20b41a18d2574e55e0af0ce67cd708"

  strings:
    $s1  = "return WScript.CreateObject(UCRbo);" fullword ascii
    $s2  = "function sPyamXwl(vke) {" fullword ascii
    $s3  = "return epIYlrG[0] + epIYlrG[2] + epIYlrG[4] + \".F\" + epIYlrG[7] + epIYlrG[9] + epIYlrG[12] + epIYlrG[14];" fullword ascii
    $s4  = "var tI = true  , rFMq = eAl[7] + eAl[9] + eAl[11];" fullword ascii
    $s5  = "var eAl = (\"2.XMLHTTP gCVrExc WRedX XML ream St nAzbFHHv AD guyatQU O ZAXR D\").split(\" \");" fullword ascii
    $s6  = "FvrRd.open(QRDWO,fDGSX,false);" fullword ascii
    $s7  = "var epIYlrG = CczMH(DUnadZdjGY+\" \"+\"System zQ BgpKQ Obj RfsLhv ect lLFYaht miPhF\", \" \");" fullword ascii
    $s8  = "function CczMH(yrD,bsbxv) {" fullword ascii
    $s9  = "function ijzS(jCYVU) {" fullword ascii
    $s10 = "return UjQCz;" fullword ascii
    $s11 = "function WaSyGqRMq(raqfS) {" fullword ascii
    $s12 = "function pxlBlrLcp(JkSIXKRKPEP) {" fullword ascii
    $s13 = "if (bKFgv > 162023-621){return true;} else {return false;}" fullword ascii
    $s14 = "return uGCD[FKjEGT[0]];" fullword ascii
    $s15 = "if(f>=h.length) {break;}" fullword ascii
    $s16 = "return vke.size;" fullword ascii
    $s17 = "function SyPN(jfMtf) {" fullword ascii
    $s18 = "return DByD.ExpandEnvironmentStrings(WfxnI);" fullword ascii
    $s19 = "if (htLBe == 497-297){return true;} else {return false;}" fullword ascii
    $s20 = "function ehPu(htLBe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}