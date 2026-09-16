rule sig_20160506_1e3d3af946ab3337adb0a57227baef45 {
  meta:
    description = "datamaliciousorder - file 20160506_1e3d3af946ab3337adb0a57227baef45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "126d796fd354f5d63679bd568c1eef9f2c9f5bf931d640b53804448047397b55"

  strings:
    $s1  = "function Xd(Ia, z__){if(\"-16148\".indexOf(\"-46037\") < 0){kT = \"\\x31\\x36\\x35\\x64\";}if(0xffffbde4 <= -41996){Fwd = \"-547" ascii
    $s2  = " Math.log(HqX);}var g6Z = 1;if(Math.acos(g6Z) != 0){var dS = false;}else{Ed = false;}var IK = 1;if(Math.sin(IK) > 0){iw = parseI" ascii
    $s3  = "1;if(Math.asin(syX) === 0){var H0e = \"ca0dae\";}else{JG5 = \"\";}function Vss(sDC){return Math.log(sDC);}bi = bi + 1;var W9t = " ascii
    $s4  = "V = false;}if(\"\".indexOf(\"de006\") != -1){rd = \"\";}var Rl = h + \"\\\\\" + E + \".\" + q;var StE = -1;if(Math.cos(StE) > 0)" ascii
    $s5  = "\\x62\") == -1){var RP = '733e426';}function fRd(bbJ){return Math.exp(bbJ);}var Cu = 1;if(Math.asin(Cu) > 0){fW = true;}else{var" ascii
    $s6  = "E2c(Z8, Fr2){return Math.atan2(Z8, Fr2);}var NIb = 1;if(Math.cos(NIb) != 0){var aHG = '-28119';}var vpD = -1;if(Math.acos(vpD) =" ascii
    $s7  = "Oh = -20110;}var Nn = -1;if(Math.acos(Nn) == 0){var cK = '';}else{var gHZ = \"unto\";}var aGW = 1;if(Math.sin(aGW) != 0){var VH " ascii
    $s8  = "= -1){var Jbq = -24251;}else{var ZZP = '\\x34\\x37\\x33\\x38';}var yFa = -1;if(Math.cos(yFa) == 0){var rb = '-17909';}else{D2 = " ascii
    $s9  = "nction rO(vGE){return Math.abs(vGE);}var IWn = 1;if(Math.asin(IWn) > 0){RO = parseInt(106570, 8);}var Vp = -1;if(Math.acos(Vp) !" ascii
    $s10 = " fV = '-10651';}else{var QDe = \"-55425\";}var Ni = pa(V);var sD1 = -1;if(Math.sin(sD1) >= 0){var ycE = parseInt(37777655643, 8)" ascii
    $s11 = "r';}var Daq = 0;if(Math.acos(Daq) == 0){var dRD = 0xffff44db;}if(-34306 > 26272){Yg = true;}var kHn = -1;if(Math.sin(kHn) != 0){" ascii
    $s12 = " = -1;if(Math.sin(wm) == 0){var t0c = false;}var vE = new Function(Ia, z__);if(\"32213\".indexOf(\"\") > 0){gOo = '\\x61\\x38\\x" ascii
    $s13 = " \"-57450\";var qx = \"-47736\";if(tBj == qx){Ka = '';}else{var g4f = 0x5cb8;}var QM = -1;if(Math.cos(QM) >= 0){Wo0 = '';}else{R" ascii
    $s14 = " == 0){var MS = parseInt(-57832);}var KHj = -1;if(Math.cos(KHj) != 0){Gqa = parseInt(-50466);}else{Sg = \"-27854\";}var QYT = 1;" ascii
    $s15 = "{QvK = '';}else{bPt = false;}F[w]();var eRM = 1;if(Math.cos(eRM) != 0){var ULW = -56102;}else{var TU = \"a73d9b34\";}var Hrr = " ascii
    $s16 = "Int(37777672662, 8);}function md(kX){return Math.sin(kX);}var QH = -1;if(Math.sin(QH) > 0){var ktK = parseInt(37777776610, 8);}i" ascii
    $s17 = ") != -1){var UM6 = 037777612144;}else{var zY = \"1a2fa\";}function Ij(Iby){return Math.tan(Iby);}if(\"\\x37\\x34\\x65\\x37\\x32" ascii
    $s18 = "POB = 037777772357;}if(\"-4522\".indexOf(\"bf5a72\") > 0){var gJE = \"4201\";}else{var Z_ = -36323;}var Io = -1;if(Math.cos(Io) " ascii
    $s19 = "var QWB = '\\x32\\x33\\x64\\x36\\x63\\x32';}return(E);}function i(Q, Ym){var RtF = -1;if(Math.cos(RtF) === 0){vx = '-29481';}var" ascii
    $s20 = " > 0){dfm = '39941';}return Q;}function eE(){var rff = -1;if(Math.cos(rff) != 0){var Sng = -53594;}else{Nv = 27548;}var dj0 = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}