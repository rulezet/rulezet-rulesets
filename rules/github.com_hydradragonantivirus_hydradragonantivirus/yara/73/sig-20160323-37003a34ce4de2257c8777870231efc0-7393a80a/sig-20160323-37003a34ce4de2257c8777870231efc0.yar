rule sig_20160323_37003a34ce4de2257c8777870231efc0 {
  meta:
    description = "datamaliciousorder - file 20160323_37003a34ce4de2257c8777870231efc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ed9d32f5b88c790d70e5f92cd83f69663f333bc363922ac198de02e19e1dfc4"

  strings:
    $s1  = "return WScript.CreateObject(yoDsX);" fullword ascii
    $s2  = "function ZsPY(mzJnt,kNXrg) {" fullword ascii
    $s3  = "return EeMdzRK[0] + EeMdzRK[2] + EeMdzRK[4] + \".F\" + EeMdzRK[7] + EeMdzRK[9] + EeMdzRK[12] + EeMdzRK[14];" fullword ascii
    $s4  = "var md = true  , BBYp = RMY[7] + RMY[9] + RMY[11];" fullword ascii
    $s5  = "var EeMdzRK = AWNWc(okOtXSxASG+\" \"+\"System ys WspsL Obj anDBGj ect XWFbjNy ycsEg\", \" \");" fullword ascii
    $s6  = "var RMY = (\"2.XMLHTTP dDjdBzP LHTDE XML ream St eLPTtshv AD RaixRSQ O TDYq D\").split(\" \");" fullword ascii
    $s7  = "HrIY.open(AYBqo,YXcbB,false);" fullword ascii
    $s8  = "function gUOKh(WwAMAJ) {" fullword ascii
    $s9  = "function VQbSKpkS(abN) {" fullword ascii
    $s10 = "function OTOY(gILhV) {" fullword ascii
    $s11 = "function qTWII(ZbkfSJ) {" fullword ascii
    $s12 = "function svGu(HzWDx,YXcbB,AYBqo) {" fullword ascii
    $s13 = "function xfmKNnbDh(rZSUi) {" fullword ascii
    $s14 = "function lVRr(LjYOd) {" fullword ascii
    $s15 = "function RCdPKnFCh(udYdZxpNCWv) {" fullword ascii
    $s16 = "KAb = n; break; " fullword ascii
    $s17 = "return vPava;" fullword ascii
    $s18 = "if (uQvdU == 488-288){return true;} else {return false;}" fullword ascii
    $s19 = "function lzrT(ythmQ) {" fullword ascii
    $s20 = "if (G >= JRCQr.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}