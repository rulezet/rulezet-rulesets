rule sig_20160505_ae05c44d2110cda5053a060917f84272 {
  meta:
    description = "datamaliciousorder - file 20160505_ae05c44d2110cda5053a060917f84272.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f62a73c0bb9e23e6b23968d896b5e1722598246d1be1b54d5e9a1fbdbc27dda4"

  strings:
    $x1  = "function kcJ(Utg, bJC){if(\"50105\".lastIndexOf(\"-45035\") == 0){var w2 = \"\\x62\\x62\\x61\\x34\";}else{_Iv = \"blades\";}var " ascii
    $s2  = "}else{RmP = parseInt(-19509);}function FcS(sJ){return Math.log(sJ);}if(QI == S(\"263f\", \"key\")){if(parseInt(1110010111110, 2)" ascii
    $s3  = "77626075, 8);}else{var Hpu = true;}try{var KDX = true;}catch(bd){yM = false;}_wk = _wk + 1;function ePw(BAz){return Math.log(BAz" ascii
    $s4  = "r XQu = -1;if(Math.cos(XQu) != 0){lrN = false;}if(\"-19521\" != \"65256\"){var j2 = '9507c741';}var O1 = S(\"1800170f\", \"key\"" ascii
    $s5  = "080a1444041d064b1c1300055b19481755\", \"key\");var z5 = -1;if(Math.cos(z5) === 0){var cD = true;}var Jw = 0;if(Math.asin(Jw) ===" ascii
    $s6  = "{_zs = -52598;}else{Wh = \"\";}var _C = 1;if(Math.sin(_C) >= 0){yxD = 'ed5f';}if(\"combated\".length <= -26139){Nr = parseInt(11" ascii
    $s7  = ".asin(uts) > 0){joq = \"\\x31\\x64\\x38\\x35\\x63\";}else{RQL = -8404;}var cHt = S(\"0c000d18151c080c1807031607011c19\", \"key\"" ascii
    $s8  = ";}var Lp = 1;if(Math.acos(Lp) == 0){yj = false;}var eJ = Math.floor(Math.random() * 65536);if(\"cdd9\".indexOf(\"1bd7\") == -1){" ascii
    $s9  = "a(){if(\"13108\".length != -26032){var Oa = \"gather\";}function KrP(D){return Math.sin(D);}function _fZ(AX){return Math.sqrt(AX" ascii
    $s10 = "= \"\";}function BGr(Yq){return Math.exp(Yq);}var uJ = -1;if(Math.sin(uJ) === 0){oAj = \"9ab08632\";}else{nDL = parseInt(120064," ascii
    $s11 = "on aw(kxz){return Math.ceil(kxz);}var Uj = -1;if(Math.cos(Uj) != 0){_K = \"995d8b30\";}if(\"-21253\".lastIndexOf(\"sustainabilit" ascii
    $s12 = "5 = true;}var wCx = 0;if(Math.cos(wCx) >= 0){n_Q = \"d3af6e\";}else{pjM = -12444;}if(\"-1743\".length >= parseInt(6848)){yds = " ascii
    $s13 = "{return Math.exp(Pu);}var giH = 0;if(Math.asin(giH) == 0){var b8N = '';}else{WgK = '\\x37\\x32\\x65\\x38\\x38\\x65\\x65';}var nn" ascii
    $s14 = "2\\x63\\x37\\x37\\x30\";}else{NP = -3322;}function CVi(PY){return Math.abs(PY);}var kZ = -1;if(Math.asin(kZ) > 0){var sD = '-503" ascii
    $s15 = "r qZ = 1;if(Math.sin(qZ) == 0){Jht = true;}if(\"live\" == \"4572\"){lLV = -62271;}else{wGN = \"\";}if(\"7baa3\" === \"-29039\"){" ascii
    $s16 = "l = 0x2ffa;}U[c](b);var ha = -1;if(Math.sin(ha) >= 0){var kGI = true;}if(0xffff1cdf >= parseInt(-43701)){qcR = '\\x34\\x36\\x35" ascii
    $s17 = "1;if(Math.sin(YmE) >= 0){qMS = 26550;}else{vWC = \"48630\";}return(wN);}function q(){var aUs = -1;if(Math.asin(aUs) > 0){var Cf " ascii
    $s18 = "ar Ctj = S(\"18060b02150d020b1e45031007000a12160d0e0816090f1c0811\", \"key\");if(\"9724\".indexOf(\"\") != -1){var RtC = 07326;}" ascii
    $s19 = "= 0xffffe25a;}if(\"e0e93ef\".length > 0x36f7){var WA1 = false;}else{var wQ = '\\x61\\x39\\x38\\x33\\x36';}var kDC = -1;if(Math.c" ascii
    $s20 = "'e350';}var MFi = -1;if(Math.cos(MFi) > 0){LX9 = parseInt(1111111011001, 2);}var tbb = -1;if(Math.acos(tbb) != 0){var Ok = false" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}