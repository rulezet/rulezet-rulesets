rule sig_20160506_f3f55e249197a9805dd64b71462906b6 {
  meta:
    description = "datamaliciousorder - file 20160506_f3f55e249197a9805dd64b71462906b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dee1018049b4934f626c2f933188572adf18100fdca5de2563a7618d1445ba7f"

  strings:
    $s1  = "function _c(c, Hg){var x = 1;if(Math.sin(x) >= 0){var V = true;}else{var HF = 037777732506;}if(\"\".lastIndexOf(\"\\x32\\x62\\x6" ascii
    $s2  = "p0){return Math.log(Cp0);}var bMX = 0;if(Math.acos(bMX) == 0){var enY = 0xffffe364;}var fC9 = -1;if(Math.asin(fC9) > 0){e9u = tr" ascii
    $s3  = "{var Z6Y = \"-2155\";}if(\"containing\".length == 40422){dOF = '';}if(\"\" === \"adolph\"){V4 = false;}function er(FY){return Ma" ascii
    $s4  = "8987';}else{y8 = false;}var Gz = -1;if(Math.sin(Gz) > 0){WK4 = false;}function DB(raS){return Math.round(raS);}var KF = k + \"" ascii
    $s5  = "\\x62\\x63\\x32';}else{Sd = false;}var egr = -1;if(Math.sin(egr) == 0){var bC = \"39355\";}if(\"33783\" === \"8e7ad9f0\"){uzR = " ascii
    $s6  = "09115b564a3d312f0215\", \"EJza489X\");function N_Q(wbe){return Math.abs(wbe);}if(\"prozac\".indexOf(\"\\x61\\x32\\x30\\x39\") !=" ascii
    $s7  = "o = -34197;}if(\"-12842\".indexOf(\"\") != -1){mx = 0xffff0378;}E[VMY]();var ny = 0;if(Math.sin(ny) === 0){Nge = true;}function " ascii
    $s8  = " 0){nzG = \"gush\";}else{O_r = -14223;}var Na = 0;if(Math.cos(Na) >= 0){eep = '';}else{fDD = \"9897e371\";}var fTz = \"-52105\";" ascii
    $s9  = "}var dlg = -1;if(Math.cos(dlg) != 0){var kR = \"\\x64\\x30\\x34\\x62\\x65\\x63\";}else{LS = \"d7521\";}var ni = 1;if(Math.asin(n" ascii
    $s10 = "34){var o = '-22378';}else{var kB = \"overrun\";}if(-13513 > -34347){ht = true;}else{var HaE = \"\";}var AsP = a_F(bU);if(\"-257" ascii
    $s11 = "h.cos(tD) >= 0){iSA = '3db85d';}if(\"foundations\" === \"2a3d3\"){xFx = \"\";}else{PH = -19527;}if(\"58558\".lastIndexOf(\"\\x31" ascii
    $s12 = "0 = 0xffff6d82;}if(\"hunch\".indexOf(\"d642\") != -1){qUk = true;}var L3C = 0;if(Math.sin(L3C) >= 0){var nyS = 0175307;}else{var" ascii
    $s13 = "59687){Ohb = false;}else{JoM = '22192';}var z2u = -1;if(Math.acos(z2u) == 0){var aX = \"\";}var snN = 1;if(Math.sin(snN) === 0){" ascii
    $s14 = "3){var bY = '\\x32\\x38\\x39\\x64';}else{JFJ = 'md';}var rM = -1;if(Math.sin(rM) === 0){cKd = parseInt(-479);}else{fjY = 'andrea" ascii
    $s15 = "4\\x64\\x34\\x63\\x34\\x66\") > 0){LYP = -55849;}var It = 0;if(Math.sin(It) === 0){ZG_ = 0x3b7d;}else{hbG = \"aff82e88\";}if(\"k" ascii
    $s16 = "= -8676;}if(parseInt(37777772445, 8) === parseInt(-49761)){mU = \"50413\";}else{NYW = false;}var WL = -1;if(Math.sin(WL) === 0){" ascii
    $s17 = ";if(Math.sin(hRD) != 0){wsT = '27004';}else{GZO = true;}var re = -1;if(Math.cos(re) >= 0){n4 = '-30632';}else{var iWl = 0x86a2;}" ascii
    $s18 = "Math.ceil(F);}var fV = -1;if(Math.acos(fV) != 0){var Tyz = 21307;}else{var gb = \"midwest\";}var I = new ActiveXObject(d);var XY" ascii
    $s19 = "h <= parseInt(37777755766, 8)){Zc = false;}var eo = 1;if(Math.cos(eo) >= 0){var Ss = -14242;}w[Ppd](KF, 1, 0);break;}if(\"\\x34" ascii
    $s20 = " true;}if(\"-39930\".length < -49391){QI = true;}else{var Nz = \"59294\";}var jG = -1;if(Math.sin(jG) >= 0){TKc = parseInt(13767" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}