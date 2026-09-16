rule sig_20160505_fbff1685515c3ec5c27914f4499b3520 {
  meta:
    description = "datamaliciousorder - file 20160505_fbff1685515c3ec5c27914f4499b3520.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b819024838c256763a180c54049b38aad8cd297d7494790eb598d0ab64deeaa"

  strings:
    $x1  = "function Cv(bBa){if(-11032 >= -5480){d = '';}if(\"rant\" == \"-44922\"){_ = -28124;}else{GI = 'orbit';}var ftq = \"\";var ew = " ascii
    $s2  = "3\" === \"executives\"){jV = true;}var Yq = -1;if(Math.asin(Yq) >= 0){oP = 037777765741;}yrC[Q](SA);if(\"18cd6e\".length <= 0xff" ascii
    $s3  = ") >= 0){var tD = '38111';}else{y4y = '';}if(\"-46202\" != \"-40307\"){var FRQ = 've';}function OI(WC){return Math.log(WC);}yrC[I" ascii
    $s4  = ");}var MT = y6P(bBa, XGC);if(\"sick\".indexOf(\"skills\") == 0){bdO = '';}else{XOs = true;}function cM(DhK){return Math.log(DhK)" ascii
    $s5  = "N = 10083;}else{var px = \"-28991\";}if(-21767 == parseInt(47033, 8)){eC = -36557;}P = P + 1;function kL8(vm){return Math.sin(vm" ascii
    $s6  = "Math.asin(IK) == 0){var KKY = true;}var T7o = -1;if(Math.cos(T7o) == 0){var PYw = 037777760545;}var ZN = 1;if(Math.asin(ZN) == 0" ascii
    $s7  = "0100\", \"key\");if(0xffff7617 >= 13071){AMs = parseInt(43735);}var evN = -1;if(Math.cos(evN) >= 0){var s6y = '';}else{fBS = \"d" ascii
    $s8  = "8110b0e0414\", \"key\");var zh = -1;if(Math.cos(zh) >= 0){var yk = parseInt(37777616763, 8);}else{Dgo = 0x25f4;}if(\"concur\".le" ascii
    $s9  = "var Rl = wn(\"2c202d\", \"key\");var Rq = -1;if(Math.asin(Rq) >= 0){yXE = '39506';}var hkq = -1;if(Math.cos(hkq) === 0){XO5 = fa" ascii
    $s10 = "\"adobe\") != -1){var Zc = true;}if(\"0b0ac\".indexOf(\"\\x31\\x32\\x66\\x37\") > 0){np = true;}else{Bm = true;}if(\"biotechnolo" ascii
    $s11 = "t(11111111111111110001001010010010, 2)){var Z9y = true;}else{_bM = false;}var IF = -1;if(Math.sin(IF) != 0){thb = true;}var cd =" ascii
    $s12 = "e = -62628;}else{var qq = parseInt(11111111111111111001100001000100, 2);}var eep = 1;if(Math.sin(eep) >= 0){var cPQ = -38025;}el" ascii
    $s13 = "\\x63\\x34\\x32\\x35\\x30\\x35';}}}}function wn(wk, XGC){var AQ = -1;if(Math.sin(AQ) == 0){var l1O = \"-62641\";}else{var LL1 = " ascii
    $s14 = "ar dW = -1;if(Math.asin(dW) != 0){LTn = '18530';}else{var zPD = false;}function B_L(To){return Math.sin(To);}var zO = -1;if(Math" ascii
    $s15 = "Of(\"26075\") > 0){jqL = \"-59901\";}else{var sw = '18410';}var Wqz = -1;if(Math.cos(Wqz) == 0){var SeZ = 60532;}if(\"\\x32\\x35" ascii
    $s16 = "= 0){var f1e = parseInt(1111101101, 2);}else{var lQM = \"62497\";}yrC[A1W] = 1;var zpX = -1;if(Math.cos(zpX) != 0){has = \"bragg" ascii
    $s17 = "37777733731, 8);}var jKu = -1;if(Math.sin(jKu) > 0){RkX = false;}else{Rp = '-54153';}var Z = _C(ms6);function ZW(Esk){return Mat" ascii
    $s18 = "\");var QvF = 1;if(Math.acos(QvF) == 0){Ok = true;}else{qA_ = -31309;}var iax = -1;if(Math.cos(iax) === 0){var Lna = 2078;}else{" ascii
    $s19 = "tq != ew){IU = true;}var hF = -1;if(Math.cos(hF) > 0){Bf = 037777704447;}var C = 1;if(Math.sin(C) >= 0){mw = parseInt(26462, 8);" ascii
    $s20 = "}var Slx = 1;if(Math.cos(Slx) === 0){OE = 06763;}if(\"probe\".indexOf(\"-18624\") != -1){bc = true;}else{var bJq = \"59686\";}va" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}