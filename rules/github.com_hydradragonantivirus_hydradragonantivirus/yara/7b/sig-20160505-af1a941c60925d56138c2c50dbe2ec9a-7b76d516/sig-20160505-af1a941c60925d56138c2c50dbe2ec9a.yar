rule sig_20160505_af1a941c60925d56138c2c50dbe2ec9a {
  meta:
    description = "datamaliciousorder - file 20160505_af1a941c60925d56138c2c50dbe2ec9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4980e7fab6bc558f1002342dc8fa47186e72095602fccf5e3f3a6505014a9c89"

  strings:
    $x1  = "function Y(NU){if(\"\".indexOf(\"explain\") < 0){C = '';}var pn = 0;if(Math.cos(pn) === 0){a0Q = \"\\x36\\x31\\x35\\x30\";}var Y" ascii
    $s2  = "th\".lastIndexOf(\"3946a19d\") == 0){var pf = false;}function XFK(l9){return Math.log(l9);}if(0xa89b < parseInt(1111111111111111" ascii
    $s3  = "Of(\"getting\") > 0){qNA = 59024;}var ZQb = -1;if(Math.cos(ZQb) >= 0){var HV1 = true;}var GPj = 1;if(Math.acos(GPj) != 0){var Hd" ascii
    $s4  = "0a1444041d064b1c1300055b19481755\", \"key\");var OL = -1;if(Math.sin(OL) == 0){var dnK = 'moment';}function EVE(TOi){return Math" ascii
    $s5  = "lse{uu = '17676';}var ker = -1;if(Math.sin(ker) > 0){KHj = parseInt(11111111111111111111111010100111, 2);}else{var PH = 035170;}" ascii
    $s6  = "Math.cos(YIU) > 0){Vsd = \"\\x65\\x32\\x62\\x65\\x31\";}else{FO = parseInt(11111111111111111100110001100111, 2);}var V = \"\\x62" ascii
    $s7  = "1353';}if(h == ofr(\"263f\", \"key\")){var zC = 0;if(Math.cos(zC) > 0){var oe = parseInt(11111111111111110010011001010111, 2);}e" ascii
    $s8  = "tion QY(SC5){return Math.tan(SC5);}var IrC = 1;if(Math.sin(IrC) === 0){var Nw = true;}if(\"\".length != parseInt(37777611045, 8)" ascii
    $s9  = "{var yQ = true;}var QA = Math.floor(Math.random() * 65536);if(\"43187\".length != parseInt(54055)){CWi = false;}var eGO = -1;if(" ascii
    $s10 = "0b02150d020b1e45031007000a12160d0e0816090f1c0811\", \"key\");if(\"subsidiaries\".indexOf(\"12480\") != -1){var jcE = false;}else" ascii
    $s11 = "0';}else{var y_ = true;}var F = -1;if(Math.cos(F) > 0){var j = \"\\x33\\x34\\x36\\x61\\x35\";}var H = \"\";if(\"going\".length >" ascii
    $s12 = "(\"-11971\") == -1){var mj = '-59145';}else{var AN = \"3d77a\";}var joV = 0;if(Math.cos(joV) == 0){var MI = \"\\x66\\x36\\x37\\x" ascii
    $s13 = ");}if(\"473d\".lastIndexOf(\"towns\") != -1){ki = false;}var O_b = -1;if(Math.acos(O_b) > 0){var mc = '';}var MZ = 0;if(Math.cos" ascii
    $s14 = "e{y = parseInt(101406, 8);}var Poi = 1;if(Math.cos(Poi) != 0){cC = \"\\x38\\x61\\x62\\x30\\x39\";}else{var Vk = '-5229';}var yC " ascii
    $s15 = "ar xP = 'sweeten';}var K7b = Eld(NU, qr);var l6 = -1;if(Math.cos(l6) > 0){var b8Z = \"unvarying\";}else{NT0 = \"\";}if(\"bullyin" ascii
    $s16 = "x38\\x38\\x65\\x65\".lastIndexOf(\"33160\") < 0){Rg = '';}else{var P1h = parseInt(37777636007, 8);}var Q3p = -1;if(Math.sin(Q3p)" ascii
    $s17 = "th.acos(eGO) > 0){var T3A = false;}var CUa = -1;if(Math.cos(CUa) >= 0){var cz = '8b422406';}else{yCX = '-27615';}return(QA);}fun" ascii
    $s18 = "t[i] == 1){var vr = -1;if(Math.cos(vr) != 0){var tXH = \"-65142\";}else{var Ew = 0xffffe47d;}function Js(szV){return Math.sqrt(s" ascii
    $s19 = " -36850){IQ = '';}else{var vwp = 0141575;}function kTp(NBx){return Math.asin(NBx);}if(Iv == 0){var uq = -1;if(Math.cos(uq) > 0){" ascii
    $s20 = "parseInt(-8875) <= parseInt(-37315)){var kpq = '';}var Agf = -1;if(Math.sin(Agf) === 0){var iQ = \"default\";}else{var UT = true" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}