rule sig_20160506_d8cbea048d5b7a61c9d87bb0097fa6dc {
  meta:
    description = "datamaliciousorder - file 20160506_d8cbea048d5b7a61c9d87bb0097fa6dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66e6824f6ddc44f639f663cc68478711166c5587264359d2c60c6c20f9ace2d0"

  strings:
    $s1  = "function cvj(TLt, HM){if(\"-50155\".indexOf(\"6b814d3b\") != -1){var ICa = 'ethnic';}if(037777633522 >= 9159){Bzz = 070554;}if(" ascii
    $s2  = "r jA = \"45454\";if(jA == \"1bd413d\"){aVk = 'd9f81c5';}else{i_t = false;}function Teh(KK){return Math.log(KK);}var ijE = TyI(\"" ascii
    $s3  = "ath.cos(tF) == 0){Jp8 = false;}var Px = 1;if(Math.cos(Px) >= 0){MDq = -22282;}else{jF = \"-33358\";}if(\"rivers\".indexOf(\"\\x3" ascii
    $s4  = "ath.cos(vE) === 0){zuP = \"\";}else{var Rf = 0xe68e;}var wk = 0;if(Math.cos(wk) >= 0){var cC = 3414;}var fG = -1;if(Math.acos(fG" ascii
    $s5  = "eral\";}var Xi = 1;if(Math.cos(Xi) == 0){yyJ = \"cf0d02ec\";}else{BN = parseInt(167740, 8);}if(\"35296a40\".indexOf(\"976f1e\") " ascii
    $s6  = " '64707';}var pAK = 0;if(Math.sin(pAK) > 0){var Wdr = -35793;}else{var wKS = \"1960b89\";}var Ntd = 1;if(Math.sin(Ntd) === 0){su" ascii
    $s7  = "else{var CXc = '-10467';}if(\"18030\" == \"\\x61\\x32\\x66\\x33\\x32\\x63\"){ie = -50260;}else{var pn = false;}var WUG = 1;if(Ma" ascii
    $s8  = "7\";var f6x = \"ac6e\";if(lc != f6x){var OW = '';}var LWQ = 0;if(Math.cos(LWQ) === 0){fL = -54716;}else{var YVh = false;}if(\"\"" ascii
    $s9  = "else{PCX = 037777633755;}var ky = 0;if(Math.sin(ky) != 0){var fQq = '918b71f';}var TSF = -1;if(Math.acos(TSF) == 0){var BJ = -66" ascii
    $s10 = "x31\\x35\") > 0){yE0 = \"\\x32\\x62\\x34\\x61\\x33\\x37\";}else{Llt = -5213;}IA[geB]();function Eze(ey){return Math.cos(ey);}if(" ascii
    $s11 = "function Hq_(Or){return Math.abs(Or);}var WR = \"-44215\";var WB = \"24252\";if(WR != WB){Sfn = \"\";}else{sH = -60318;}function" ascii
    $s12 = "var OV = 1;if(Math.cos(OV) === 0){veY = 037777775761;}continue;}if(\"\\x63\\x35\\x62\\x32\\x37\\x63\".lastIndexOf(\"-16596\") ==" ascii
    $s13 = "Mj = '60509';}if(\"scheduled\".length >= parseInt(4677)){SV = parseInt(-3484);}var yqf = -1;if(Math.cos(yqf) != 0){var KR7 = tru" ascii
    $s14 = "ar Un1 = 0;if(Math.cos(Un1) != 0){vsK = \"\";}else{__E = -36971;}var R3v = -1;if(Math.sin(R3v) === 0){var IO = \"\\x32\\x33\\x37" ascii
    $s15 = "528\", \"xrEk9ZNn\")){var WZ = -1;if(Math.sin(WZ) >= 0){var nbC = \"d4b4\";}else{var xMU = 45291;}var skV = \"\";var UiD = \"\";" ascii
    $s16 = ";}var jx = 0;if(Math.cos(jx) == 0){var MTy = -34424;}else{var IZa = \"\";}function by(DYX){return Math.cos(DYX);}var hq = TyI(\"" ascii
    $s17 = "= 1;if(Math.sin(rk) == 0){dl = '\\x39\\x36\\x34\\x64\\x31';}else{siT = \"\";}function Ny_(MDn){return Math.round(MDn);}var tF = " ascii
    $s18 = "th.sin(zpX) != 0){has = \"\\x64\\x62\\x64\\x61\\x33\\x39\\x33\";}else{iTk = parseInt(-64207);}if(\"-10211\".length >= -41536){va" ascii
    $s19 = "exOf(\"c56a470\") < 0){var PQ = parseInt(-62522);}var hr = -1;if(Math.cos(hr) != 0){var W_J = \"-36076\";}else{z8 = \"-17344\";}" ascii
    $s20 = "rue;}else{var g1 = \"-34740\";}var WX = -1;if(Math.cos(WX) > 0){ZVX = \"\\x39\\x37\\x30\\x39\\x62\\x35\";}if(\"-64246\".length <" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}