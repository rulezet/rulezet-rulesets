rule sig_20160310_c1ff91a9e959674cb675525c4da07061 {
  meta:
    description = "datamaliciousorder - file 20160310_c1ff91a9e959674cb675525c4da07061.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ced9dfc7172cf6871e3f766ccded6e7167754312934d01526a1171c8afb71a8"

  strings:
    $s1  = "var Us = true  , akId = VnM[7] + VnM[9] + VnM[11];" fullword ascii
    $s2  = "return KTCERgD[0] + KTCERgD[2] + KTCERgD[4] + \".F\" + KTCERgD[7] + KTCERgD[9] + KTCERgD[12] + KTCERgD[14];" fullword ascii
    $s3  = "kzONN.open(rPsLh,YijrR,false);" fullword ascii
    $s4  = "var KTCERgD = \"Sc notABJz r eooizmxil ipting iysamcn Vam ile tXuQkIhHqvpUFy System Nd ObJmo Obj aTGXQQ ect mohucOE\".split(\" " ascii
    $s5  = "var VnM = (\"2.XMLHTTP JLVhjYi BCfXb XML ream St PxDHwCDB AD MdkOrwC O ABKg D\").split(\" \");" fullword ascii
    $s6  = "return qpaV.responseBody;" fullword ascii
    $s7  = "return ujV.size;" fullword ascii
    $s8  = "if (O >= LwymB.length) {break;}" fullword ascii
    $s9  = "function oAgiskPYU(wrYWm,VswUz,hengS,QXvM) {" fullword ascii
    $s10 = "function fgQT(pFFtH) {" fullword ascii
    $s11 = "function eKOl(NqvEh,snDYb) {" fullword ascii
    $s12 = "function QRUZ(RQbrN) {" fullword ascii
    $s13 = "return new ActiveXObject(rzgHer);" fullword ascii
    $s14 = "function NDKPGBZ(qpaV) {" fullword ascii
    $s15 = "return lEoN.ExpandEnvironmentStrings(rWxYU);" fullword ascii
    $s16 = "if (pFFtH > 158349-530){return true;} else {return false;}" fullword ascii
    $s17 = "function BYwdiupH(ujV) {" fullword ascii
    $s18 = "function aJOk(lmDnn) {" fullword ascii
    $s19 = "return ybSYbv.position=230-230;" fullword ascii
    $s20 = "function YbhPYgCw(vgmNX,GMAYRD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}