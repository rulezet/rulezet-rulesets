rule sig_20160323_3770d110d870d2f659a224a0931d5c98 {
  meta:
    description = "datamaliciousorder - file 20160323_3770d110d870d2f659a224a0931d5c98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8acbe60a71e23fd0d842e8698edbf1d597dec596c682958354783bf5d5bf790"

  strings:
    $s1  = "return WScript.CreateObject(NDBlI);" fullword ascii
    $s2  = "return yOHUBos[0] + yOHUBos[2] + yOHUBos[4] + \".F\" + yOHUBos[7] + yOHUBos[9] + yOHUBos[12] + yOHUBos[14];" fullword ascii
    $s3  = "var gK = true  , MchB = nEr[7] + nEr[9] + nEr[11];" fullword ascii
    $s4  = "var nEr = (\"2.XMLHTTP qAMCLKE gKxei XML ream St woULhNgv AD KLzeiPf O yuME D\").split(\" \");" fullword ascii
    $s5  = "ccHb.open(VfQTx,Nixgd,false);" fullword ascii
    $s6  = "var yOHUBos = iHVxE(OjvfqcFMFU+\" \"+\"System ZS FHSfE Obj wOrxCb ect thzYjic ADaxx\", \" \");" fullword ascii
    $s7  = "if(t>=d.length) {break;}" fullword ascii
    $s8  = "function LanDP(ksEkQT) {" fullword ascii
    $s9  = "function keddXSGR(YOT) {" fullword ascii
    $s10 = "function DVfrtQTf(sOwZ) {" fullword ascii
    $s11 = "function hTJSB(yEJQuy) {" fullword ascii
    $s12 = "function yhWY(tQCIv) {" fullword ascii
    $s13 = "rsr = t; break; " fullword ascii
    $s14 = "function FaoY(dVTrO,BNjhm) {" fullword ascii
    $s15 = "return tMgv[lgUhAs[0]];" fullword ascii
    $s16 = "function WwHsuvlWV(CDZaJCBAmnj) {" fullword ascii
    $s17 = "function iHVxE(ULm,qyBDJ) {" fullword ascii
    $s18 = "return yEJQuy/*QMEuWhqagOn1c0vVEQrjdrGMx*/.position=102-102;" fullword ascii
    $s19 = "function cMeZ(Vhqph,Nixgd,VfQTx) {" fullword ascii
    $s20 = "function HRpSXiVvG(webQA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}