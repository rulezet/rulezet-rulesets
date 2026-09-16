rule sig_20160405_2d13394a72b7fcca0afd88b1d251d67f {
  meta:
    description = "datamaliciousorder - file 20160405_2d13394a72b7fcca0afd88b1d251d67f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2217a700bd471386f0c19475e802759192ee6c7aa10c12d9385ee4b4d56e33"

  strings:
    $s1  = "var Ct = true  , GcJk = QOW[7] + QOW[9] + QOW[11];" fullword ascii
    $s2  = "return sxTPeLT[0] + sxTPeLT[2] + sxTPeLT[4] + \".F\" + sxTPeLT[7] + sxTPeLT[9] + sxTPeLT[12] + sxTPeLT[14];" fullword ascii
    $s3  = "var QOW = (\"2.XMLHTTP gZlthzT IcDVY XML ream St RPziSGqe AD ADbfluY O fZys D\").split(\" \");" fullword ascii
    $s4  = "jbnO.open(yEVdf,UTSLx,false);" fullword ascii
    $s5  = "if(E>=y.length) {break;}" fullword ascii
    $s6  = "function qOac(UxTzS,UTSLx,yEVdf) {" fullword ascii
    $s7  = "function QqEWBr(yQANNYW) {" fullword ascii
    $s8  = "function uJZyOpBFz(PnqEW) {" fullword ascii
    $s9  = "if (fVsYc == 713-513){return true;} else {return false;}" fullword ascii
    $s10 = "function xrEHNYbj(dNk) {" fullword ascii
    $s11 = "function GzVRYXB(aOEi) {" fullword ascii
    $s12 = "function mAQMLzKgl(MrIfTUIGdbR) {" fullword ascii
    $s13 = "return VlIePFb[0];" fullword ascii
    $s14 = "if (vdDNq > 158945-192){return true;} else {return false;}" fullword ascii
    $s15 = "return BKqd;" fullword ascii
    $s16 = "return QwSqJ.status;" fullword ascii
    $s17 = "function djcy(QwSqJ) {" fullword ascii
    $s18 = "return LpK.split(gmoGZ);" fullword ascii
    $s19 = "function KNVe(JVDRO,UNiDL) {" fullword ascii
    $s20 = "function vBbcd(HSmZIo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}