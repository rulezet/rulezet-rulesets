rule sig_20160507_6c955948172cc39bb08aa09065158e19 {
  meta:
    description = "datamaliciousorder - file 20160507_6c955948172cc39bb08aa09065158e19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22d866819bbb76a4dc8b48de019898ef85afd6f9e25b37642e915ce1f2b0f533"

  strings:
    $x1  = "function Uaf(kd, IA){function I(k){return Math.floor(k);}var kj = -1;if(Math.asin(kj) != 0){eIg = '-28911';}if(\"-29132\".length" ascii
    $s2  = ") != -1){var H8p = \"45449\";}function aA8(SYm){return Math.log(SYm);}var qHI = -1;if(Math.sin(qHI) == 0){var nc = 037777763575;" ascii
    $s3  = " 'b5928e5c';}if(\"aafd834\".length < parseInt(37777616551, 8)){var Iyg = '96f2';}function hrL(ePd){return Math.log(ePd);}var ZX " ascii
    $s4  = "seInt(37777774631, 8);}var lGn = 0;if(Math.sin(lGn) === 0){Ics = '889091';}else{WRZ = true;}var st = -1;if(Math.asin(st) != 0){v" ascii
    $s5  = "tralize\".length <= -40220){NcE = false;}else{sX = parseInt(18393);}var Uh3 = 1;if(Math.cos(Uh3) == 0){var gF = \"55263\";}var G" ascii
    $s6  = ") != -1){var Szb = parseInt(-11777);}else{var yyD = \"841115c\";}var yEs = 0;if(Math.cos(yEs) == 0){jCd = '-34356';}else{pE = tr" ascii
    $s7  = " = false;}var JTp = 0;if(Math.sin(JTp) > 0){var _j = '49795';}else{var Ygy = \"59930\";}Y[TZ](geB + \" \" + f + \" \" + NVh, 1, " ascii
    $s8  = " HQ0(eJ){return Math.asin(eJ);}var rES = -1;if(Math.sin(rES) == 0){sA = \"17b8be\";}else{var u2 = 'triangle';}var Bv_ = 0;if(Mat" ascii
    $s9  = "= 1;if(Math.sin(Fd) > 0){var fhZ = -63224;}else{CC = 037777675052;}if(\"\\x39\\x62\\x30\\x31\\x62\".indexOf(\"\\x37\\x64\\x64\\x" ascii
    $s10 = "ar Nw = 20051;}else{f1X = -63250;}return(L);}function m8r(_){var OTK = 0;if(Math.cos(OTK) == 0){var JTb = '\\x64\\x37\\x30\\x35" ascii
    $s11 = "unction d(){function dO(WtU){return Math.cos(WtU);}if(\"-39181\".indexOf(\"\\x63\\x63\\x37\\x31\\x39\\x62\\x31\") == 0){ia = \"" ascii
    $s12 = ";var zY = -1;if(Math.acos(zY) == 0){fo_ = -50160;}var UN_ = 0;if(Math.cos(UN_) >= 0){yyR = \"\";}else{dy5 = -21183;}if(\"0d04a4" ascii
    $s13 = "e;}var wDr = -1;if(Math.sin(wDr) >= 0){Lk = true;}else{var oyC = '-38966';}if(-33809 < 0x3839){QbS = '';}var In = \"\\x34\\x38" ascii
    $s14 = " 0xc228;}var ERr = 0;if(Math.sin(ERr) > 0){var NS = 0xffff42b6;}else{VDB = -46867;}var Q3p = H(\"20062e1207\", \"WtGfbup\");if(" ascii
    $s15 = " Sws(n){return Math.cos(n);}if(\"18d59\".length == -40210){var vD = \"-9979\";}else{Vo = \"a3116fcb\";}if(\"-54020\" == \"-14766" ascii
    $s16 = "c2\".indexOf(\"\\x37\\x35\\x36\\x30\\x64\\x38\") < 0){cru = false;}var fQ = 0;if(Math.sin(fQ) > 0){wKt = -30401;}else{VQ = '5aba" ascii
    $s17 = "\");}var Dn = -1;if(Math.asin(Dn) >= 0){var zVS = 071404;}var GR5 = 0;if(Math.sin(GR5) >= 0){vk = 0xffffe4d3;}else{var BJN = fal" ascii
    $s18 = "r l = -1;if(Math.sin(l) > 0){HC = 0xfffff7d8;}else{var J3 = true;}if(\"\".lastIndexOf(\"honduras\") < 0){cN = false;}else{var bw" ascii
    $s19 = "eturn Math.exp(TyK);}var cZ = 1;if(Math.acos(cZ) > 0){var uv0 = false;}if(34513 < parseInt(166770, 8)){var vYY = -8686;}var Y = " ascii
    $s20 = "an(zIJ);}var aGV = -1;if(Math.cos(aGV) != 0){t2b = \"\";}if(\"-64292\".length > -38120){var ZLk = '';}else{var Vv = false;}if(\"" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}