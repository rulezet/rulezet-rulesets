rule sig_20160419_0f0bd478929f3d10f5fb57cdf6f3f16c {
  meta:
    description = "datamaliciousorder - file 20160419_0f0bd478929f3d10f5fb57cdf6f3f16c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac068c69f79259053e44a4b8c6fd047a760a5720d9d3f4f5dff93a63f91ba5b"

  strings:
    $s1  = "return CZzkHoU[0] + CZzkHoU[2] + CZzkHoU[4] + \".F\" + CZzkHoU[7] + CZzkHoU[9] + CZzkHoU[12] + CZzkHoU[14];" fullword ascii
    $s2  = "var Jn = true  , sdYQ = sCv[7] + sCv[9] + sCv[11];" fullword ascii
    $s3  = "LDEo.open(Jmboi,TaOKB,false);" fullword ascii
    $s4  = "var sCv = (\"2.XMLHTTP rTPbZzs BBdjh XML ream St iIsomNub AD UyfWlVl O gpAe D\").split(\" \");" fullword ascii
    $s5  = "function TlSJp(YuVauN) {" fullword ascii
    $s6  = "return dZQTs;" fullword ascii
    $s7  = "function Vytt(CbCKQ) {" fullword ascii
    $s8  = "return WpczV.status;" fullword ascii
    $s9  = "function wmHkc(oyQkZvuB,VJiq) {" fullword ascii
    $s10 = "function hQrC(ZDbTT) {" fullword ascii
    $s11 = "function OTueEA(qpsm,FxKRpv) {" fullword ascii
    $s12 = "if(n>=R.length) {break;}" fullword ascii
    $s13 = "if (OrxtN > 177438-544){return true;} else {return false;}" fullword ascii
    $s14 = "oZM = n; break; " fullword ascii
    $s15 = "function aGsq(QrPjD,TaOKB,Jmboi) {" fullword ascii
    $s16 = "return YuVauN[cHxY[652-652]]=176-176;" fullword ascii
    $s17 = "function hXKGv(ytgpxu) {" fullword ascii
    $s18 = "return UimjXXf(Ld,ywqyRY+YhbAl[155-147]);" fullword ascii
    $s19 = "function KqHJ(hAAcO,dtBZW) {" fullword ascii
    $s20 = "function kddN(OrxtN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}