rule sig_20160506_8803dea4f32f842b39c48d10718b45ea {
  meta:
    description = "datamaliciousorder - file 20160506_8803dea4f32f842b39c48d10718b45ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d853812b379dee83a78cbbc56b47aaab296f9446ba236ee53eb1757532b8f242"

  strings:
    $s1  = "function H(ztw){var xVn = 1;if(Math.acos(xVn) != 0){var xe = 'serve';}if(\"\".indexOf(\"60976\") > 0){Y_C = 'tipsy';}else{qvV = " ascii
    $s2  = "){Trj = parseInt(-51529);}else{var xxk = true;}function q(Zg){return Math.log(Zg);}var FBS = 0;if(Math.cos(FBS) > 0){CY = \"ea5d" ascii
    $s3  = "n nBi(UM6){return Math.log(UM6);}if(parseInt(37777617075, 8) < 0xa540){var Cj = \"\";}if(\"d250\".length === parseInt(-31744)){v" ascii
    $s4  = "ontractor\"){qH = '82e532e';}if(\"\" != \"\"){AVc = '';}function hBU(KG){return Math.log(KG);}var i = bS(\"5633131f425c5658370b0" ascii
    $s5  = " = true;}function F7(qal){return Math.abs(qal);}var H1 = Hu + \"\\\\\" + Y8 + \".\" + jx;if(\"-55800\".length == -3242){var DQ =" ascii
    $s6  = "Math.acos(yrC) > 0){hT = \"loins\";}var fOb = -1;if(Math.cos(fOb) === 0){var IA = false;}var q5i = -1;if(Math.sin(q5i) == 0){yg " ascii
    $s7  = ") < 0){var pD = -9504;}var kZ = \"operative\";if(kZ == \"\"){var zwp = '71f2a0';}var P5i = HPS(_Pb);if(0110645 == -50063){NSo = " ascii
    $s8  = "\\x62\\x37\"){_LG = 0xffff15f8;}else{Yh = \"0292118\";}if(\"\".lastIndexOf(\"\") > 0){WB = -59993;}else{pRi = 'compliance';}var " ascii
    $s9  = "seInt(-20552)){Pya = 'b13bba';}else{var jU = 58015;}var Y8 = Math.floor(Math.random() * 65536);var WRN = 0;if(Math.cos(WRN) != 0" ascii
    $s10 = "){return Math.sin(cSW);}if(\"cdeb62c\".indexOf(\"dec\") == -1){var ny = '-48905';}if(parseInt(37777677317, 8) === 0x31a8){NDE = " ascii
    $s11 = "eInt(37777613173, 8) <= -57989){zPX = 56915;}else{var yPm = false;}var kG = 1;if(Math.cos(kG) === 0){rRz = 'basque';}var Yf = -1" ascii
    $s12 = "= false;}var dw = -1;if(Math.cos(dw) != 0){Ck = parseInt(-23019);}return(F);}pC();" fullword ascii
    $s13 = "2960\";}else{GV_ = parseInt(37777663360, 8);}if(0xffff5bee < -59296){var ZF = 'distributions';}function v6(OXd){return Math.cos(" ascii
    $s14 = "];if(\"47244\".lastIndexOf(\"-18964\") == -1){_0y = \"34171\";}else{HC = 0172012;}var MGa = 1;if(Math.cos(MGa) >= 0){var HL = 0x" ascii
    $s15 = "7755114, 8)){Jon = parseInt(-6758);}var nxG = -1;if(Math.sin(nxG) >= 0){y2c = false;}else{P9 = 'release';}if(\"\".lastIndexOf(\"" ascii
    $s16 = " xBP = 1;if(Math.acos(xBP) != 0){var Mve = '\\x65\\x66\\x34\\x65\\x33\\x62\\x37\\x37';}else{var RV = false;}var XK0 = -1;if(Math" ascii
    $s17 = "if(\"a883bb\".indexOf(\"819ba5\") == -1){bU = false;}else{var ZOv = \"36757\";}var EOV = 0;if(Math.sin(EOV) > 0){tUs = -11607;}v" ascii
    $s18 = "2\\x63\\x39\\x64\") == 0){var a9 = '\\x36\\x35\\x39\\x62\\x37\\x62\\x34';}else{gIc = 'ffba';}var kI = -1;if(Math.sin(kI) === 0){" ascii
    $s19 = ";}function CUX(Uvm){return Math.floor(Uvm);}var NO = -1;if(Math.cos(NO) > 0){var Vq = 0xffff85da;}var nE = bS(\"3b124a2c3c03211f" ascii
    $s20 = ");var TNz = 1;if(Math.sin(TNz) > 0){Ks = \"\";}else{var nfK = 'dbe2b7e9';}if(\"16389be\".lastIndexOf(\"97e4df\") == -1){g4 = par" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}