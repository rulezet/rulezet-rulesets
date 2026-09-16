rule sig_20160506_fa4b86c1857d26800013841ea419d7c8 {
  meta:
    description = "datamaliciousorder - file 20160506_fa4b86c1857d26800013841ea419d7c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2bad7d433d936c2d8a9703d28f86482ae0cf0c1147aacb2ffca3a66c215f9a1"

  strings:
    $x1  = "function M(O8){var Ue = 0;if(Math.cos(Ue) != 0){var Nb_ = parseInt(37777625657, 8);}if(\"potion\".length < parseInt(-24607)){n =" ascii
    $s2  = "Of(\"79fde54\") == -1){var DC = '';}function rn4(ivq){return Math.log(ivq);}var Bm = k(\"3a311822153a6079\", \"HDvFyVSK\");if(\"" ascii
    $s3  = "f(jy === \"62975\"){Ho = parseInt(-37443);}else{var wj = true;}var zyf = -1;if(Math.sin(zyf) > 0){tU = 'encompass';}else{var uC " ascii
    $s4  = "H + \"\\\\\" + Lz + \".\" + DXa;var YlP = -1;if(Math.sin(YlP) != 0){var xg = true;}if(-7940 >= -14456){var Bt1 = '';}var kgm = " ascii
    $s5  = "x = \"hosted\";}var G = Ch[_CM];var x8X = -1;if(Math.acos(x8X) === 0){var iw = false;}if(\"8182\".length == 22715){NX = '22016';" ascii
    $s6  = "cca(Slx){return Math.log(Slx);}function ZM(Xy){return Math.acos(Xy);}var Nmi = 1;if(Math.asin(Nmi) === 0){var IN_ = 037777736546" ascii
    $s7  = "){return Math.asin(PM);}if(\"19654\".length <= -52486){var Vw = -13494;}var Lz = Math.floor(Math.random() * 65536);var Wa = \"-2" ascii
    $s8  = "exOf(\"\\x64\\x32\\x31\\x30\\x61\\x31\") != -1){var Rzl = parseInt(-10965);}var d6C = 0;if(Math.cos(d6C) != 0){var sEf = true;}i" ascii
    $s9  = "Ex) > 0){kft = \"\";}else{kL8 = -22341;}var D = k(\"3a020242110012193e19045c14\", \"Mqa0xpf7\");var Gr = 1;if(Math.cos(Gr) > 0){" ascii
    $s10 = "e{xb = 9539;}var l = new Array();var mj = 1;if(Math.sin(mj) >= 0){Ll = true;}if(\"reliable\".length >= -36001){var t8Y = 'freedo" ascii
    $s11 = "x61\\x39';}else{var xWM = true;}var eC = -1;if(Math.cos(eC) > 0){var P_M = \"-27813\";}else{var go = parseInt(-47674);}var c6p =" ascii
    $s12 = "30\"){clm = true;}var Q6_ = 0;if(Math.sin(Q6_) >= 0){gD = -64649;}else{var xW8 = 'loathsome';}var g = M(xy);if(\"43778\" != \"" ascii
    $s13 = "return Math.atan(X7);}function ChL(LXY){return Math.tan(LXY);}var D5 = -1;if(Math.asin(D5) > 0){var Fnw = '-34209';}if(r == k(\"" ascii
    $s14 = " 0xffffbf9e){p2 = '';}else{var AX9 = parseInt(14083);}if(0x3fcd == parseInt(48010)){A1W = '941a';}var xQT = -1;if(Math.cos(xQT) " ascii
    $s15 = "Pf = \"ten\";}var dFz = -1;if(Math.cos(dFz) >= 0){var RM = true;}else{var iHh = 22357;}var r = Ch[b].substr(0, 2);function hF(X7" ascii
    $s16 = " Sws = -1;if(Math.sin(Sws) >= 0){var e_ = \"\";}else{var ZZ6 = false;}var t = M(kGI);var Rl = 1;if(Math.sin(Rl) != 0){wSK = '-11" ascii
    $s17 = "H = -1;if(Math.cos(UH) == 0){var _r = '\\x36\\x64\\x33\\x33';}else{xuu = '-15417';}function IN(rUi){return Math.cos(rUi);}var zw" ascii
    $s18 = " > 0){GjV = parseInt(37777620373, 8);}var Ch = M(Y);var IH = -1;if(Math.sin(IH) === 0){VA = -38337;}else{var C_T = false;}var U2" ascii
    $s19 = "in(P) == 0){var VR = parseInt(30637, 8);}return(c);}function mO7(EX, AzA){var Lt = -1;if(Math.sin(Lt) > 0){var zW = -42919;}else" ascii
    $s20 = "\"\\x63\\x36\\x32\\x32\";if(zwN != \"98465\"){Xi = -42108;}else{var kb = true;}g[ql](c6p);var Yoc = 0;if(Math.cos(Yoc) === 0){va" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}