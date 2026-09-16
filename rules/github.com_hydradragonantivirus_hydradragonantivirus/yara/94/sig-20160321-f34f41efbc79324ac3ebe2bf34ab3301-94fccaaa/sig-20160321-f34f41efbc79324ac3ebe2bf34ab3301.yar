rule sig_20160321_f34f41efbc79324ac3ebe2bf34ab3301 {
  meta:
    description = "datamaliciousorder - file 20160321_f34f41efbc79324ac3ebe2bf34ab3301.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e43d71ef9b1c4a5060a26efe9658f9913341eb86bec6b2e8bf14ffc0fbea7ef7"

  strings:
    $s1  = "return WScript.CreateObject(mThyy);" fullword ascii
    $s2  = "return FQpEQyL[0] + FQpEQyL[2] + FQpEQyL[4] + \".F\" + FQpEQyL[7] + FQpEQyL[9] + FQpEQyL[12] + FQpEQyL[14];" fullword ascii
    $s3  = "var wU = true  , kQgc = xlW[7] + xlW[9] + xlW[11];" fullword ascii
    $s4  = "var FQpEQyL = cZBVe(hCmwRIzBhT+\" \"+\"System rm nhyrw Obj bmhZQE ect XPXpQmx FEBPn\", \" \");" fullword ascii
    $s5  = "function yLAY(rUnpu) {" fullword ascii
    $s6  = "BFkIO.open(cSWQG,CjbiJ,false);" fullword ascii
    $s7  = "var xlW = (\"2.XMLHTTP NfWVTds ZPaTi XML ream St TYwXKnEQ AD bCQoggw O hGwO D\").split(\" \");" fullword ascii
    $s8  = "if(q>=d.length) {break;}" fullword ascii
    $s9  = "function dRMi(Lvptw) {" fullword ascii
    $s10 = "if (smHCo > 189157-254){return true;} else {return false;}" fullword ascii
    $s11 = "function Nfrk(BFkIO,CjbiJ,cSWQG) {" fullword ascii
    $s12 = "return ppP.size;" fullword ascii
    $s13 = "return Ssgaj;" fullword ascii
    $s14 = "function BZhpEfQTJ(xQmlS) {" fullword ascii
    $s15 = "function zzOYI(TJxryg) {" fullword ascii
    $s16 = "function aeIy(muOhR,RSPoD) {" fullword ascii
    $s17 = "function sEnb(mThyy) {" fullword ascii
    $s18 = "function mHwk(smHCo) {" fullword ascii
    $s19 = "return WQU.split(XIsZK);" fullword ascii
    $s20 = "bYT = q; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}