rule sig_20160506_fe0fc3c4d297ea1f6f66d7260737887c {
  meta:
    description = "datamaliciousorder - file 20160506_fe0fc3c4d297ea1f6f66d7260737887c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2519b8d5b325f480c21bfbf265b48df72f87585684439bc6e182fa9c27561e6"

  strings:
    $x1  = "function D(t){var ScS = 0;if(Math.asin(ScS) > 0){var VH = \"\\x38\\x63\\x30\\x34\\x36\\x39\\x64\\x61\";}else{qNA = '\\x35\\x64" ascii
    $s2  = "-1){tDU = \"\";}var eC = 1;if(Math.asin(eC) > 0){var Cl = 0xaf66;}else{kBs = -42994;}function tQF(axk){return Math.log(axk);}if(" ascii
    $s3  = "x62\\x35\\x33\\x62\";}else{var fc1 = '-37293';}function qH(jg){return Math.log(jg);}if(\"25719\".length == 0xb5c5){aZ = \"dui\";" ascii
    $s4  = "f(parseInt(-20182) != 0x4f9d){var tD = '55171';}else{y4y = '-33969';}function ECb(Yc){return Math.log(Yc);}var U = BVk(\"0e313f2" ascii
    $s5  = "nt(30491)){var mJ = \"\";}else{Xr = \"d4cd\";}var II = D(qQ);if(\"temps\".indexOf(\"\") == 0){var t8Y = '-1801';}if(\"-21972\".l" ascii
    $s6  = " = 1;if(Math.asin(UF) != 0){var F2 = 'e65d4c41';}else{zzu = 'encompass';}function eZZ(NC){return Math.sin(NC);}NlC[YTn]();functi" ascii
    $s7  = "r _G = 0;if(Math.acos(_G) != 0){kY = \"-15915\";}else{btF = true;}var uSK = Fp + \"\\\\\" + pBY + \".\" + u;if(\"\".indexOf(\"c1" ascii
    $s8  = "1;if(Math.cos(FY) > 0){var Gwj = \"-36626\";}else{var rUi = 0xffff0280;}var r3F = -1;if(Math.sin(r3F) == 0){var lbc = \"tip\";}v" ascii
    $s9  = "0){var RtC = 3375;}function ut(Ex){return Math.tan(Ex);}NlC[GW] = 1;var Gr = -1;if(Math.sin(Gr) > 0){var mk4 = \"41731\";}else{v" ascii
    $s10 = "t(48095);}var JAc = 1;if(Math.asin(JAc) != 0){KM = '';}var l2w = -1;if(Math.cos(l2w) >= 0){rZ = false;}var E = \"\";if(02051 <= " ascii
    $s11 = "(Math.cos(JO5) != 0){var Xt = 'cancer';}Tj = Tj + 1;var _M = -1;if(Math.sin(_M) > 0){usp = '17788';}try{var Up = false;}catch(ar" ascii
    $s12 = "tinue;}var ZzM = 0;if(Math.sin(ZzM) == 0){Qn = 'sd';}else{var bn = -5073;}var Qzf = 0;if(Math.acos(Qzf) > 0){var tr = true;}else" ascii
    $s13 = "else{var Kv = 0x9426;}var z_ = -1;if(Math.cos(z_) != 0){var My = \"zenith\";}else{var UI = true;}if(\"reliance\".length != 24484" ascii
    $s14 = "os(tKK) === 0){QE = false;}else{var DBs = \"\\x33\\x63\\x31\\x63\\x64\";}var Iim = -1;if(Math.cos(Iim) > 0){var e3 = \"467f\";}v" ascii
    $s15 = "oS = new Array();var lo = 0;if(Math.cos(lo) != 0){var qju = true;}else{var eJD = '\\x37\\x65\\x64\\x31\\x33\\x38\\x38\\x38';}var" ascii
    $s16 = "rseInt(55155)){h8 = \"-2772\";}var ddP = -1;if(Math.asin(ddP) == 0){Ic = true;}var at = 1;if(Math.sin(at) === 0){OOW = \"21547\"" ascii
    $s17 = "64779;}var DhK = -1;if(Math.cos(DhK) === 0){var eRS = false;}else{var XUT = '59930';}var RYL = 1;if(Math.cos(RYL) != 0){var JXQ " ascii
    $s18 = ".length <= 0x7549){var Cha = true;}else{var nvU = '5463';}var Qyg = -1;if(Math.sin(Qyg) >= 0){var os = true;}var J = BVk(\"09132" ascii
    $s19 = ")){var Rzl = -1046;}else{var CLe = \"18882\";}o_n[k0Y](uSK, 1, 0);break;}var _ow = -1;if(Math.cos(_ow) == 0){var Atc = parseInt(" ascii
    $s20 = " II[vNW];if(\"\".length != -39720){var Ju = true;}var ct = 0;if(Math.sin(ct) >= 0){Fh = \"\";}var Y7T = \"\\x66\\x39\\x63\\x34" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}