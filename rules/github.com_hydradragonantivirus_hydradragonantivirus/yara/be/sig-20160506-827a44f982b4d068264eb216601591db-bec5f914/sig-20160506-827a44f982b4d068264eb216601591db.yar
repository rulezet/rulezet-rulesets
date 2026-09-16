rule sig_20160506_827a44f982b4d068264eb216601591db {
  meta:
    description = "datamaliciousorder - file 20160506_827a44f982b4d068264eb216601591db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f260f3ed4fd5c06be452c39ac8cf265eb552736ee17f70be4a2aec5c21e032aa"

  strings:
    $x1  = "function r(gY, uvu){var Z = \"\\x36\\x62\\x65\\x37\\x39\";var rER = \"-9854\";if(Z === rER){SJ = '28787';}var LB = 1;if(Math.asi" ascii
    $s2  = "}else{Cv = -48804;}function GJW(Ur){return Math.log(Ur);}if(0145537 < 33917){var kz = false;}else{x = false;}var N = 0;function " ascii
    $s3  = "\\x39\".indexOf(\"-39313\") > 0){gaD = -19673;}var YG = 0;if(Math.sin(YG) > 0){BC = false;}var D5 = Sx + \"\\\\\" + L + \".\" + " ascii
    $s4  = " = -12268;}var Ku = \"41536\";if(Ku != \"passwords\"){QM = '\\x61\\x61\\x39\\x39\\x30';}else{var gI = parseInt(-48359);}var aOs " ascii
    $s5  = ";}var L = Math.floor(Math.random() * 65536);if(0x4352 === -26020){var Nwh = '';}else{var jr = true;}var Pl = 0;if(Math.sin(Pl) >" ascii
    $s6  = "Math.round(MG);}var gd = -1;if(Math.asin(gd) >= 0){uKy = false;}var T = 1;if(Math.cos(T) > 0){var vhX = 11026;}else{var XLj = \"" ascii
    $s7  = "arseInt(-2117)){var A = false;}if(0xf155 != 2120){pID = \"twos\";}var nQK = 1;if(Math.sin(nQK) === 0){var ve = \"script\";}var o" ascii
    $s8  = "\\x38\\x39\";}Gp[lDc]();var xKo = 1;if(Math.cos(xKo) >= 0){jR4 = '';}else{ny = true;}var Sh = -1;if(Math.asin(Sh) != 0){var P8 =" ascii
    $s9  = "\\x39\\x38\\x36\";if(kd === \"magazine\"){dah = '';}else{var Nx = -48685;}var q3 = -1;if(Math.cos(q3) != 0){var To = true;}else{" ascii
    $s10 = ") < 0){var YR = \"-15113\";}else{jg = \"47847\";}var PrK = new ActiveXObject(G);var nDL = -1;if(Math.sin(nDL) === 0){var RN = 0x" ascii
    $s11 = "r wRR = \"shower\";}var tg = -1;if(Math.asin(tg) >= 0){var JUQ = \"-58449\";}else{Da = \"-5988\";}var gY = \"\";var HJ = 0;if(Ma" ascii
    $s12 = "\"-111\") != -1){var lM7 = 037777636354;}var Mp7 = 0;if(Math.cos(Mp7) >= 0){D5Y = 037777731407;}else{Mxw = \"\";}function CXc(JD" ascii
    $s13 = "XV(WI){return Math.abs(WI);}if(\"61502\".length != 33683){MU = parseInt(9305);}else{var lV = false;}var Dro = -1;if(Math.cos(Dro" ascii
    $s14 = "== 0){var at = false;}else{yi = true;}var Bol = -1;if(Math.cos(Bol) >= 0){var ilX = '';}else{var kB = false;}if(\"\".lastIndexOf" ascii
    $s15 = "= false;}if(\"747e\".indexOf(\"\\x30\\x33\\x35\\x64\\x34\") > 0){jh = 29612;}var jSb = -1;if(Math.cos(jSb) >= 0){var C8e = \"164" ascii
    $s16 = "t(-18672);}if(\"29521\".length >= -47385){Ej = \"\";}var Sx = aOs[Kp](2);function uLq(FCl){return Math.tan(FCl);}var GbG = 0;if(" ascii
    $s17 = "){var iGC = 1;if(Math.cos(iGC) == 0){var iA = false;}else{Npr = false;}if(\"2781\".indexOf(\"\\x32\\x66\\x36\\x30\\x31\") != -1)" ascii
    $s18 = "on MZ(HrN){return Math.exp(HrN);}var Bu = \"\\x38\\x63\\x32\\x66\\x35\\x66\\x39\\x35\";if(Bu != \"godmother\"){var hwC = true;}v" ascii
    $s19 = "tK != uHY){var ks = true;}else{vH = false;}var e1R = -1;if(Math.cos(e1R) === 0){DSd = '49092';}else{kyV = true;}if(\"2286\".last" ascii
    $s20 = " = '\\x36\\x37\\x63\\x31';}function yos(_o){return Math.cos(_o);}var Fl = -1;if(Math.cos(Fl) >= 0){var Jc = '2dfd';}else{In = ''" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}