rule sig_20160507_15a6cb4aa47186d5b74ebcbde12d1c85 {
  meta:
    description = "datamaliciousorder - file 20160507_15a6cb4aa47186d5b74ebcbde12d1c85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9248f49e01438304315b3b948379d3ca3d8017ec36ed92debedca20b23880095"

  strings:
    $x1  = "function JFt(b){var T0y = 1;if(Math.cos(T0y) === 0){var N = \"18624\";}if(\"\\x63\\x34\\x33\\x31\\x39\\x36\\x31\\x32\".lastIndex" ascii
    $s2  = " = 'saucepan';}else{var yP = false;}if(\"56562\".lastIndexOf(\"\") < 0){mM = '';}function lbP(gT){return Math.log(gT);}if(parseI" ascii
    $s3  = "ath.cos(Kw) != 0){TW = 0x9dd2;}else{P8j = '';}var MuS = 0;if(Math.acos(MuS) >= 0){zfi = \"subsequently\";}var Zbz = -1;if(Math.c" ascii
    $s4  = "function JFt(b){var T0y = 1;if(Math.cos(T0y) === 0){var N = \"18624\";}if(\"\\x63\\x34\\x33\\x31\\x39\\x36\\x31\\x32\".lastIndex" ascii
    $s5  = "ength >= -28990){Qe4 = \"ap\";}var GM = 0;if(Math.asin(GM) == 0){EbJ = \"41240\";}else{dfg = 2640;}Ekq = Ekq + 1;if(\"vernacular" ascii
    $s6  = "\\x63\\x64\\x33\\x33\\x65\\x39\".length == 48103){Q1q = false;}var A = LF[FrV];var mH3 = -1;if(Math.sin(mH3) != 0){BPI = parseIn" ascii
    $s7  = "26, 8);}var qO = \"4474\";if(qO === \"\"){XPN = '';}else{var bSV = -56385;}function gYL(vS){return Math.sin(vS);}var Cwn = nuq[P" ascii
    $s8  = "parseInt(2803) >= 52108){var fo = \"36752\";}hx[Q]();var eH = 0;if(Math.acos(eH) > 0){Fw = false;}var iWl = -1;if(Math.cos(iWl) " ascii
    $s9  = "61\\x36\\x66\\x33\\x39\\x61\\x31';}function kT(Z0){return Math.round(Z0);}var _h = -1;if(Math.sin(_h) === 0){var Aiw = \"\";}els" ascii
    $s10 = "534, 8);}var WB = -1;if(Math.sin(WB) === 0){var ii0 = 'a5eb6';}else{var LPR = false;}if(\"\\x30\\x32\\x62\\x32\\x39\" == \"46665" ascii
    $s11 = "var Z_ = 0x58fc;}if(\"13170ed0\".lastIndexOf(\"fbdbfd\") != -1){WDv = '9ed1';}else{var WF = parseInt(30254);}var wF = -1;if(Math" ascii
    $s12 = " = -1;if(Math.sin(oD) >= 0){var Gz = 0x7d8;}else{FWg = 60670;}for(PwS = 0; PwS < nuq.length; PwS++){try{var O3Z = \"65366\";if(O" ascii
    $s13 = "in(ZL);}var kh = -1;if(Math.acos(kh) === 0){var i_ = '';}else{var fOL = \"bed72a7\";}var nM = -1;if(Math.sin(nM) === 0){var TI =" ascii
    $s14 = "1){var tiW = '28906';}var v6L = -1;if(Math.cos(v6L) != 0){var ZYO = \"\\x61\\x63\\x37\\x31\";}else{var M3P = parseInt(34988);}va" ascii
    $s15 = "p = -44125;}else{var gV = true;}var xd = 0;if(Math.sin(xd) >= 0){var f1e = 0x263a;}var B4 = 1;if(Math.acos(B4) === 0){var sC1 = " ascii
    $s16 = " noO = parseInt(126262, 8);}var n = AUo(\"372b27115a050401312b2c15\", \"ENTa5kwd\");var MK = -1;if(Math.cos(MK) != 0){wt = '';}e" ascii
    $s17 = "d(_0);}var Z8q = -1;if(Math.sin(Z8q) >= 0){var Btq = false;}var kd = 1;if(Math.sin(kd) === 0){var d_ = \"\\x33\\x63\\x62\\x31\";" ascii
    $s18 = "= 0;if(Math.acos(EKH) === 0){var j3F = true;}var KPh = pMp(DJk, uLM);if(-9092 < -43126){Yl = true;}var PJ = 1;if(Math.sin(PJ) ==" ascii
    $s19 = "seInt(42619);}if(\"belt\".length === 0xffff07c9){var nte = \"21451\";}hx[oI]();var Ia = -1;if(Math.sin(Ia) == 0){var iQ = false;" ascii
    $s20 = ";var Rz = \"-53353\";if(pW == Rz){var heo = false;}else{var _Pm = '';}var o3 = -1;if(Math.sin(o3) === 0){HwZ = parseInt(-5221);}" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}