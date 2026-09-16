rule sig_20160507_b06fa03cc224914c84c7eccb1fd1243f {
  meta:
    description = "datamaliciousorder - file 20160507_b06fa03cc224914c84c7eccb1fd1243f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adb11e654799c918b88c4c260606eec82039c148341059ceee4e7e215f020609"

  strings:
    $x1  = "function u(k, B6){function wA(B){return Math.tan(B);}if(parseInt(8250) < -60237){var Cym = true;}else{var tb = '28713';}if(0xfff" ascii
    $s2  = "dn = 'pittsburgh';}function Ho(Mmu){return Math.sqrt(Mmu);}function Ea(Vz){return Math.log(Vz);}var T3A = -1;if(Math.sin(T3A) ==" ascii
    $s3  = "7a(EZg){return Math.log(EZg);}var RnY = xkx(\"1d3c121c097a5a26090252381026090a5634076614191c64477848094b3009781a5d4f655920121843" ascii
    $s4  = "chapters';}var ZaI = -1;if(Math.asin(ZaI) >= 0){NsD = false;}else{xHj = 'configure';}FDU[bVC] = 1;var nL = -1;if(Math.sin(nL) ==" ascii
    $s5  = "10852\".indexOf(\"31933\") == -1){var smA = true;}else{var vV = '\\x63\\x64\\x66\\x34';}if(\"f946\".indexOf(\"hackneyed\") != -1" ascii
    $s6  = "f(snN === \"\\x37\\x65\\x66\\x66\\x65\\x33\\x36\"){var zJ = true;}if(\"\".indexOf(\"\") == -1){sDa = '';}r[RiY](wo + \" \" + kw " ascii
    $s7  = "t(55277)){NGi = 037777631765;}var pf = -1;if(Math.sin(pf) != 0){VE = \"-13563\";}else{RhS = false;}var Q = new Array();var Gt = " ascii
    $s8  = "o = \"\";}var Sw = -1;if(Math.cos(Sw) > 0){R6 = '-9113';}else{var tRJ = parseInt(37777601720, 8);}var pP = RnY[q].split(\"|\");i" ascii
    $s9  = "c';}else{u2_ = '63702';}var gs = -1;if(Math.sin(gs) === 0){aMm = '27072';}else{R4 = false;}FDU[SUF](kw);if(\"\\x64\\x37\\x37\\x6" ascii
    $s10 = "3;}else{TRn = 62076;}var CF = -1;if(Math.cos(CF) >= 0){dg = true;}if(015111 < parseInt(6784)){_0y = \"omega\";}function MGa(cQT)" ascii
    $s11 = "D = -1;if(Math.cos(gnD) != 0){nuC = false;}var P = mW(m);if(\"-51364\".lastIndexOf(\"\\x62\\x62\\x39\\x63\\x61\\x64\\x36\\x30\")" ascii
    $s12 = "sz = true;}if(\"lookup\".length == 0134154){YPN = \"enervated\";}else{var pZ0 = '\\x62\\x38\\x34\\x39\\x62\\x31\\x30\\x61';}var " ascii
    $s13 = "1;if(Math.cos(qQ) > 0){a3 = false;}else{Zh = parseInt(-381);}if(\"\".indexOf(\"gist\") < 0){var OsP = -54368;}return k;}function" ascii
    $s14 = " === 0){var _EK = -64796;}var Lz = xkx(\"33275b\", \"WK7p6BVT\");}else{var G4r = -1;if(Math.sin(G4r) == 0){Nl = false;}var kHn =" ascii
    $s15 = ";if(Math.sin(Gt) >= 0){IFR = false;}else{XLr = true;}if(\"-12595\".length >= -28392){dY = \"brevity\";}else{var zIO = -5008;}if(" ascii
    $s16 = "function OL(Nn){return Math.round(Nn);}var z = \"6877\";if(z == \"-58592\"){var kpD = 0xffff7e49;}var THA = -1;if(Math.sin(THA) " ascii
    $s17 = "\"\";}var SYK = 1;if(Math.sin(SYK) >= 0){var KH = \"22043\";}function E(OIY){return Math.sin(OIY);}if(\"-5283\".length > -20456)" ascii
    $s18 = " > 0){var niy = \"88059058\";}else{var POB = 0xffffd46e;}var _G4 = -1;if(Math.cos(_G4) == 0){var gJE = \"51437\";}var r = mW(d);" ascii
    $s19 = "e{var iO3 = 'brilliant';}var Ydv = 0;if(Math.cos(Ydv) > 0){var qwX = -64333;}else{var gq = \"18000\";}var bVC = xkx(\"333a4057\"" ascii
    $s20 = "function u(k, B6){function wA(B){return Math.tan(B);}if(parseInt(8250) < -60237){var Cym = true;}else{var tb = '28713';}if(0xfff" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}