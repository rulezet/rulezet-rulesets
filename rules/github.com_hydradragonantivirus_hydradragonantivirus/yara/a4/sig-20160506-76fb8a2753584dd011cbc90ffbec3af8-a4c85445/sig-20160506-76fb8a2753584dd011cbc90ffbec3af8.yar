rule sig_20160506_76fb8a2753584dd011cbc90ffbec3af8 {
  meta:
    description = "datamaliciousorder - file 20160506_76fb8a2753584dd011cbc90ffbec3af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f9a314fbb3e4d118cb4de2f331ca0119182af9c3478ed7a13e8d5c0aacd532"

  strings:
    $s1  = "function eH(V){if(-64458 >= -17241){Y = parseInt(3510);}function fvs(GOL){return Math.log(GOL);}var yjB = 0;if(Math.sin(yjB) == " ascii
    $s2  = "){return Math.log(Ub);}if(\"51204\".indexOf(\"6d12\") != -1){xDI = 0x48c9;}var ycE = 1;if(Math.cos(ycE) === 0){var Yo = \"-27745" ascii
    $s3  = "function eH(V){if(-64458 >= -17241){Y = parseInt(3510);}function fvs(GOL){return Math.log(GOL);}var yjB = 0;if(Math.sin(yjB) == " ascii
    $s4  = "8;}function bd(SRC){return Math.log(SRC);}if(parseInt(73144, 8) > 60714){var BI = true;}if(G[o] == 1){var qG = \"f85809\";if(qG " ascii
    $s5  = "1\";}else{var Po = 30299;}var boH = -1;if(Math.sin(boH) >= 0){YXe = \"-21990\";}else{cS = 37840;}ru[D](_cE + \" \" + kk + \" \" " ascii
    $s6  = "r zW5 = false;}var G = new Array();var oU = \"together\";if(oU != \"51445\"){pEt = true;}var iax = -1;if(Math.acos(iax) > 0){var" ascii
    $s7  = "\\x33\\x34\\x33\\x38\") != -1){VP = true;}var U4 = 1;if(Math.asin(U4) == 0){ByV = parseInt(15976);}var AA = 1;if(Math.cos(AA) ==" ascii
    $s8  = "x33\\x66\\x65\\x39\") == -1){var QuH = '24345';}var avs = 0;if(Math.sin(avs) === 0){var uWJ = \"32696\";}else{var aJD = parseInt" ascii
    $s9  = " = 9636;}var A = qWT[3];if(-25122 < -11700){var OMx = \"25368\";}else{uB = \"scenic\";}var Pqk = 0;if(Math.cos(Pqk) == 0){kY = 0" ascii
    $s10 = "x39\\x38\\x66';}function eZs(eJ){return Math.sin(eJ);}var WX = -1;if(Math.asin(WX) != 0){ZVX = \"\\x35\\x31\\x39\\x33\\x62\\x64" ascii
    $s11 = "lse{var jyh = 0xa2a5;}var bY = X(\"51345c\", \"5X0GzqZ\");}else{var Lt = -1;if(Math.cos(Lt) > 0){var zW = parseInt(37777757024, " ascii
    $s12 = "8)){WtI = parseInt(29136);}var Hna = -1;if(Math.sin(Hna) > 0){var It = true;}else{var j8P = parseInt(28247);}if(\"36841\".indexO" ascii
    $s13 = ".length >= parseInt(14966)){var Av = '8c76';}var Fr2 = -1;if(Math.sin(Fr2) == 0){var uWy = '55601';}else{var TNX = false;}functi" ascii
    $s14 = "37\\x35\".lastIndexOf(\"\") > 0){LzN = true;}else{vbY = '3524';}if(\"48369\".indexOf(\"\") < 0){Ck = 0x683b;}var Cv = -1;if(Math" ascii
    $s15 = " = \"57365\";}var aPa = 1;if(Math.sin(aPa) != 0){var xmO = -50199;}else{var _Lp = '-31784';}function gU(wx){return Math.exp(wx);" ascii
    $s16 = "x31\\x35\\x31\"){var KH = 'ofries';}function tXK(Yl){return Math.ceil(Yl);}var BM = 0;if(Math.sin(BM) != 0){gL = -4410;}if(\"\\x" ascii
    $s17 = ";}function W9t(vYF){return Math.cos(vYF);}var Ke = -1;if(Math.cos(Ke) == 0){var KlS = \"d1ee896\";}else{var ip = -45063;}try{var" ascii
    $s18 = "32\".length === -38924){var wWF = false;}if(\"a579f35\".length >= 0xd81c){fg = parseInt(40681);}else{var CFI = true;}if(\"17961" ascii
    $s19 = "h.cos(v6L) === 0){oo3 = '\\x63\\x39\\x37\\x64\\x30';}var DH = -1;if(Math.acos(DH) != 0){var j3F = true;}else{var A4m = '\\x61\\x" ascii
    $s20 = "46\";}else{cQo = '3af1c3';}var JV = 1;if(Math.sin(JV) === 0){var mgk = \"-56259\";}else{var LO = -26376;}if(\"-51080\" != \"273c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}