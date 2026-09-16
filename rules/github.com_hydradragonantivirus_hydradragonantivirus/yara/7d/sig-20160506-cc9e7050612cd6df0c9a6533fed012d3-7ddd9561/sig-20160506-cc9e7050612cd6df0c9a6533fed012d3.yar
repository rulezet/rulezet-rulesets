rule sig_20160506_cc9e7050612cd6df0c9a6533fed012d3 {
  meta:
    description = "datamaliciousorder - file 20160506_cc9e7050612cd6df0c9a6533fed012d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff33b0f6cc29fc45b90268f848b53b9a7b50b1ad68eac943e07fd94d11c8656e"

  strings:
    $s1  = "function R(i, W){if(\"14617\".length === 0xffff7f1a){p = true;}else{dqU = parseInt(-15563);}var N = 0;if(Math.asin(N) == 0){XQ =" ascii
    $s2  = "ar l = new ActiveXObject(G);function uHY(jV){return Math.log(jV);}if(\"\\x34\\x30\\x61\\x66\".length <= -48624){mu = false;}else" ascii
    $s3  = "rdiff';}var hT = 0;if(Math.sin(hT) >= 0){_K = 'bin';}function _Y7(FY){return Math.log(FY);}i += String.fromCharCode(parseInt(xG3" ascii
    $s4  = "X = 037143;}else{SeF = \"logged\";}var C = new Array();var up = -1;if(Math.sin(up) == 0){var jon = 0xffffbf02;}else{var FV = \"" ascii
    $s5  = " \".\" + n;if(\"2555b\" === \"\"){sFl = true;}var FUM = -1;if(Math.asin(FUM) === 0){Cg = -2975;}else{YyM = true;}if(parseInt(-15" ascii
    $s6  = "e;}if(0x7db7 != 61814){var Tk = false;}if(\"8134\" === \"\"){ZqO = -54057;}var Idh = Math.floor(Math.random() * 65536);var FD = " ascii
    $s7  = "\\x34\\x38\\x62\\x63\".indexOf(\"rankings\") < 0){Vsd = \"2089\";}var zwN = -1;if(Math.sin(zwN) != 0){Xi = 0xffff5d20;}else{var " ascii
    $s8  = "f49a\".length != -64985){var ZIG = '-19173';}else{rUc = \"d401\";}var HNd = 0;if(Math.cos(HNd) >= 0){var qR = parseInt(-35997);}" ascii
    $s9  = "K = true;}else{var i3 = \"0b74e\";}if(M[KVg] == 200){var qP = 1;if(Math.cos(qP) != 0){P5 = \"65c17\";}else{var L_ = -50177;}func" ascii
    $s10 = "m(EzT){return Math.cos(EzT);}if(\"52727\".indexOf(\"-35401\") == -1){var NZf = parseInt(-6978);}var XY = 0;if(Math.asin(XY) >= 0" ascii
    $s11 = "Pbm = \"\";}var _ = new Function(z, HZJ);var dQ = -1;if(Math.sin(dQ) > 0){var c = parseInt(37777617751, 8);}if(\"\\x32\\x32\\x65" ascii
    $s12 = ";}var KSl = -1;if(Math.cos(KSl) > 0){jEw = \"\\x37\\x37\\x63\\x34\\x39\\x33\\x65\\x63\";}if(\"eagles\".length < 25103){var ce2 =" ascii
    $s13 = "R(\"0a23260717\", \"iOItr74e\");if(\"\".lastIndexOf(\"9c9b996\") == 0){BIR = false;}var _h = -1;if(Math.cos(_h) >= 0){var Aiw = " ascii
    $s14 = "{if(\"11958d\".lastIndexOf(\"\") > 0){vTY = parseInt(-34043);}else{lFO = \"\\x38\\x63\\x66\\x65\\x64\\x66\\x66\\x38\";}var UT = " ascii
    $s15 = "nction qD(RFJ){return Math.sqrt(RFJ);}var ThP = -1;if(Math.sin(ThP) != 0){var LPd = -36502;}else{var tH = \"leaflet\";}var Y = R" ascii
    $s16 = "rseInt(102024, 8);}else{D1L = \"3df8\";}var BGr = 1;if(Math.sin(BGr) === 0){oRU = -16023;}else{yS = \"58967\";}var SAG = parseIn" ascii
    $s17 = "5) == 0){iWI = 'impotence';}var zY = -1;if(Math.sin(zY) > 0){var f9 = true;}else{O_q = true;}continue;}if(\"-15070\".indexOf(\"2" ascii
    $s18 = " rnI = 037777640227;}var pw = -1;if(Math.sin(pw) != 0){var RWa = 0xffffc23f;}function VHy(tld){return Math.acos(tld);}function P" ascii
    $s19 = "e{jJ = false;}j[g]();var dL = -1;if(Math.cos(dL) != 0){var hD = parseInt(-18727);}if(54352 != -44518){var H8p = \"19821\";}else{" ascii
    $s20 = " false;}if(44966 <= -56336){GA = 0xffff607a;}else{ddP = '\\x36\\x39\\x32\\x36\\x65\\x61';}var JRs = 0;if(Math.sin(JRs) != 0){var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}