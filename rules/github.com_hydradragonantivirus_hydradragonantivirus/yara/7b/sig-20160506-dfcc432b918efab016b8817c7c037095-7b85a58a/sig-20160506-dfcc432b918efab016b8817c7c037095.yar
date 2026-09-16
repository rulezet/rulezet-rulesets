rule sig_20160506_dfcc432b918efab016b8817c7c037095 {
  meta:
    description = "datamaliciousorder - file 20160506_dfcc432b918efab016b8817c7c037095.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58984e906e2848defe68d88f3d00b140c9c9729c042d7082066b42470491276"

  strings:
    $s1  = "function GY(fC, m6e){function GoF(X){return Math.sin(X);}if(parseInt(13032) >= -48163){iyZ = 'andros';}else{yBm = true;}if(\"556" ascii
    $s2  = "0){var Gk = \"\";}else{Jw = \"d923\";}function PHn(ZT){return Math.log(ZT);}for(Ji = 0; Ji < o1.length; Ji++){try{var bn = -1;if" ascii
    $s3  = "ath.floor(Math.random() * 65536);if(\"-21021\".length == -1629){var bvO = false;}function bfX(XzK){return Math.abs(XzK);}var KiN" ascii
    $s4  = "n Math.log(nSw);}var sTL = 1;if(Math.cos(sTL) === 0){Nv = '';}var Tn = \"\\x62\\x39\\x32\\x33\\x64\";if(Tn != \"41026\"){CH_ = " ascii
    $s5  = "490){v_Z = false;}else{Ck = -44374;}if(\"\\x63\\x30\\x30\\x62\".indexOf(\"-63406\") == 0){var knj = false;}var I_ = Kv + \"" ascii
    $s6  = "\"\";}var pZs = 1;if(Math.acos(pZs) >= 0){D = 0xffff708f;}else{var l6 = \"spoilt\";}if(Dz >= m6e.length){var wg = -1;if(Math.sin" ascii
    $s7  = "4 = -1;if(Math.sin(l54) != 0){var VFA = 037777733643;}if(\"\".length <= 29062){c0 = parseInt(37777753657, 8);}else{var Ow5 = \"" ascii
    $s8  = "39\\x35\") < 0){pY = -32618;}else{var FAh = true;}var wW = 1;if(Math.cos(wW) >= 0){var DW = \"38481\";}else{rd = \"48131\";}cont" ascii
    $s9  = "\", \"5NUXsEfn\");}var uq = 0;if(Math.asin(uq) != 0){IV = '18177';}var fvM = 0;if(Math.cos(fvM) != 0){var Vww = -46839;}else{var" ascii
    $s10 = "function GY(fC, m6e){function GoF(X){return Math.sin(X);}if(parseInt(13032) >= -48163){iyZ = 'andros';}else{yBm = true;}if(\"556" ascii
    $s11 = "r rEr = 0;if(Math.cos(rEr) > 0){var LG = true;}else{gr = false;}var _bh = -1;if(Math.asin(_bh) === 0){var VXt = '47102';}else{va" ascii
    $s12 = "h.acos(qA) >= 0){EJZ = parseInt(35222);}else{var R_m = false;}var _j = -1;if(Math.sin(_j) > 0){var wc4 = \"coincident\";}var gIl" ascii
    $s13 = "1\", \"hvm3WTG\");}else{var qqm = 1;if(Math.sin(qqm) > 0){si = \"fbcb03\";}if(\"2cb274e\".lastIndexOf(\"16493\") == -1){GYJ = \"" ascii
    $s14 = "lse;}if(\"fawn\".lastIndexOf(\"ea81a3\") != -1){ZG = 0x2c3c;}else{var uHi = false;}var PTh = 1;if(Math.sin(PTh) > 0){var KH = \"" ascii
    $s15 = "Kw = 1;if(Math.cos(Kw) == 0){var eo_ = parseInt(34391);}else{kU = -12744;}if(parseInt(112010, 8) < 0xffff515a){var etl = \"e0040" ascii
    $s16 = "\".lastIndexOf(\"-55446\") < 0){Csd = \"brownie\";}if(\"\".length != 037777715015){ms = \"\";}else{Yg = \"36952a\";}var bm = -1;" ascii
    $s17 = " _C = 'ointment';}function ZD(hHP){return Math.tan(hHP);}var ekS = 1;if(Math.acos(ekS) === 0){var YFt = -18715;}else{var YHP = " ascii
    $s18 = " -1){rw = false;}if(64676 >= 0141656){var QQ = 037777727232;}function Hof(IO){return Math.tan(IO);}return fC;}function zv(){if(" ascii
    $s19 = " iI = 0;if(Math.cos(iI) >= 0){var jR = 'handjob';}else{jtb = '';}if(\"-35977\".indexOf(\"\\x33\\x30\\x36\\x65\\x65\") != -1){var" ascii
    $s20 = "urn Math.tan(GG);}var nQa = -1;if(Math.asin(nQa) == 0){var yF = true;}else{yi = false;}for(var F = 0; F < Pi.length; F += 2){if(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}