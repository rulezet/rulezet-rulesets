rule sig_20160404_749a95fecc1f3de08090a1314f0a7420 {
  meta:
    description = "datamaliciousorder - file 20160404_749a95fecc1f3de08090a1314f0a7420.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6dc387be47d2e7716fe7e5a249bfb222ac691b64bb4cd3310df2ce3b43f0ea"

  strings:
    $s1  = "var qhf = wPGN(lAnk + \"B.\" + Fpi[5]+(591625, Fpi[4]));" fullword ascii
    $s2  = "return wZrOoZH[0] + wZrOoZH[2] + wZrOoZH[4] + \".F\" + wZrOoZH[7] + wZrOoZH[9] + wZrOoZH[12] + wZrOoZH[14];" fullword ascii
    $s3  = "var rA = true  , lAnk = Fpi[7] + Fpi[9] + Fpi[11];" fullword ascii
    $s4  = "oOTA.open(xFouI,HbSTy,false);" fullword ascii
    $s5  = "var wZrOoZH = BcpJQ(zwRurKBmRr+\" \"+\"System Dn MmRHs Obj vlCUth ect AhrLyJT Usmsc\", \" \");" fullword ascii
    $s6  = "return lytHpun;" fullword ascii
    $s7  = "function GMMM(mhcBa) {" fullword ascii
    $s8  = "function ldGZ(piJFp,AAVnO) {" fullword ascii
    $s9  = "function BcpJQ(fgX,SlCdt) {" fullword ascii
    $s10 = "function yoKN(sNdQo,HbSTy,xFouI) {" fullword ascii
    $s11 = "if (MXxwL > 167290-103){return true;} else {return false;}" fullword ascii
    $s12 = "if (PAXaS == 386-186){return true;} else {return false;}" fullword ascii
    $s13 = "function sMkhxAB(bYKV) {" fullword ascii
    $s14 = "function WPLN(SxMSv) {" fullword ascii
    $s15 = "function XjAJ(Arsbr) {" fullword ascii
    $s16 = "function eaJXF(jUEVvdEe,oyOe) {" fullword ascii
    $s17 = "var SolXgXC = \"GZYUUT*Fkd*pt.S\"+\"hell*VIWNvsN*Scri*\";" fullword ascii
    $s18 = "if(Y>=r.length) {break;}" fullword ascii
    $s19 = "Rtp = Y; break; " fullword ascii
    $s20 = "return BWOkQtf;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}