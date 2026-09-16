rule sig_20160506_e30b483a9afac07c6d1517c37b4cc4c4 {
  meta:
    description = "datamaliciousorder - file 20160506_e30b483a9afac07c6d1517c37b4cc4c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "969db68e15031e08c220a63997f5e5e12faf4ba89ad73a52c78af10345265a09"

  strings:
    $s1  = "function K3r(){var F = 0;if(Math.asin(F) === 0){var LCH = '-16457';}var eB = 0;if(Math.sin(eB) === 0){pEE = 'indeterminate';}var" ascii
    $s2  = "rn Math.log(LL1);}if(\"-59779\".length < parseInt(25606)){w2J = 0xa4cb;}var Xbv = -1;if(Math.cos(Xbv) != 0){yWa = true;}if(\"359" ascii
    $s3  = "= parseInt(38666);}if(-60427 < 0xffff238b){NFh = 19415;}else{zcx = \"\";}function rAp(e5o){return Math.log(e5o);}var W = NO(\"03" ascii
    $s4  = "th.sin(ulj) > 0){var ZZ = '3b5f';}else{Dg = '11477';}var J = V[1];if(\"\\x66\\x35\\x65\\x39\\x61\\x63\\x36\\x62\".indexOf(\"-427" ascii
    $s5  = "}var S3V = XcD(Iu);var RS = -1;if(Math.sin(RS) == 0){u6i = true;}else{var er = \"\";}var wmK = 0;if(Math.cos(wmK) == 0){var tiW " ascii
    $s6  = "\"-62791\".length == 026021){zYc = false;}var Srf = 0;if(Math.cos(Srf) == 0){var yn7 = 'theft';}if(077456 < -2176){var HUe = tru" ascii
    $s7  = "'\\x31\\x30\\x38\\x66\\x65\\x31';}else{var r8 = false;}var v6L = -1;if(Math.sin(v6L) === 0){var ZYO = \"\";}else{var M3P = 0x936" ascii
    $s8  = ";if(Math.cos(tH) == 0){Oo = '49799';}if(\"-4657\".length > -41434){var TC = -40803;}else{cf8 = -11125;}var knj = NO(\"1c3a254717" ascii
    $s9  = ") < 037777667047){KLD = 'flaxen';}var By = 1;if(Math.sin(By) === 0){FW = \"\\x36\\x66\\x66\\x32\";}else{d5 = false;}var ulj = -1" ascii
    $s10 = "ffffb2e5;}if(43999 > -342){Vu = \"\\x63\\x33\\x66\\x64\\x63\\x62\\x36\\x62\";}else{var JX4 = '-48056';}var MK = 0;if(Math.cos(MK" ascii
    $s11 = "x63\\x63\\x31\\x64\\x66\";}var YF = -1;if(Math.cos(YF) > 0){oG = false;}var hfe = OH[nc];var Vp = 1;if(Math.cos(Vp) >= 0){wEl = " ascii
    $s12 = "r K_3 = -1;if(Math.sin(K_3) > 0){var jY = '-25651';}else{sDa = '';}var j = -1;if(Math.cos(j) > 0){hHj = true;}else{m = 'my';}var" ascii
    $s13 = "1\".length < -64073){var fu = parseInt(37777607077, 8);}else{QsX = -47261;}var xc = XcD(Gf);var Vs = 1;if(Math.cos(Vs) == 0){var" ascii
    $s14 = "}var fc1 = -1;if(Math.sin(fc1) === 0){var fo = \"51135\";}else{B2i = \"niger\";}if(parseInt(22460) > 47845){var GRr = 0xb863;}xc" ascii
    $s15 = "Ck = 30899;}T = T + 1;var n2J = 1;if(Math.sin(n2J) != 0){var Q4s = \"\";}var RW = 0;if(Math.cos(RW) != 0){rBs = true;}else{kcJ =" ascii
    $s16 = "';}if(\"-59536\".length > 0x12a4){var Wfl = false;}var Md = -1;if(Math.cos(Md) >= 0){var hFg = '\\x64\\x33\\x31\\x61';}else{vo =" ascii
    $s17 = "Qh = Math.floor(Math.random() * 65536);if(50863 == parseInt(-29156)){var g = '-50217';}function y(VE){return Math.abs(VE);}funct" ascii
    $s18 = "= \"\\x33\\x39\\x35\\x38\\x62\";}else{var Osc = parseInt(-40681);}var jG = 1;if(Math.sin(jG) > 0){var b3 = -6920;}else{enT = 560" ascii
    $s19 = "sh);}var pe8 = 1;if(Math.asin(pe8) != 0){rC = false;}else{bq = 0xffff7504;}var XLj = -1;if(Math.cos(XLj) >= 0){var Fr = true;}el" ascii
    $s20 = ")){EX = false;}else{var OS = \"-26971\";}var kk = 0;if(Math.cos(kk) == 0){Lk = -687;}else{var oyC = '-32599';}var hd = 1;if(Math" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}