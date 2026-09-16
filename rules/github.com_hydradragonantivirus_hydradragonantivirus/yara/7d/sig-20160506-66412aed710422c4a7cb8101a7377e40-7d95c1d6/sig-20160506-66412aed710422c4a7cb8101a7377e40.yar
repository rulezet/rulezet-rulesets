rule sig_20160506_66412aed710422c4a7cb8101a7377e40 {
  meta:
    description = "datamaliciousorder - file 20160506_66412aed710422c4a7cb8101a7377e40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5ff8d7de77739a26099ac206b4270b547ba1059b1edd5ed958c55cc77f5251e"

  strings:
    $s1  = "function isR(wXF, ra){if(\"-65341\" === \"52048\"){N = parseInt(37777640636, 8);}else{a = '';}var c = 1;if(Math.acos(c) === 0){v" ascii
    $s2  = "on gK(Csd){return Math.sin(Csd);}function Mt_(SWb){return Math.log(SWb);}var fED = s(\"272c201e\", \"TINzDd6P\");var C2W = 1;if(" ascii
    $s3  = "J9m = 'comparable';}var dc = 1;if(Math.acos(dc) === 0){fq = 23345;}else{gYL = '38461';}var kkk = W[0];var s6V = -1;if(Math.sin(s" ascii
    $s4  = "= '';}if(0xffffef9c > -51641){var iHE = '3f2798';}else{var jQ = true;}var k = Math.floor(Math.random() * 65536);if(parseInt(-507" ascii
    $s5  = "608;}if(g == s(\"2f2d\", \"bwqMiJ\")){if(\"\".indexOf(\"\") != -1){EY2 = '8307';}else{xQg = false;}function ux(QW){return Math.c" ascii
    $s6  = "egion\".lastIndexOf(\"do\") == 0){var Cha = false;}else{var nvU = '';}var Qyg = -1;if(Math.sin(Qyg) === 0){var os = true;}var ls" ascii
    $s7  = "r U = -1;if(Math.sin(U) > 0){var aOs = 49190;}var z = kHn(b);var o3S = 1;if(Math.asin(o3S) >= 0){var Fg = false;}else{SvM = true" ascii
    $s8  = "Math.atan(fDF);}var mb = \"-38136\";if(mb != \"\"){var Rzl = 0xffffd29f;}else{var K_j = \"\";}var d6C = -1;if(Math.asin(d6C) == " ascii
    $s9  = "parseInt(115101, 8);}var wnU = -1;if(Math.sin(wnU) === 0){T8F = '';}var dL = \"\";if(dL != \"risky\"){var hn = 57012;}else{_Yp =" ascii
    $s10 = "unction Ij(Iby){return Math.tan(Iby);}wy = 0;}}var dFz = 1;if(Math.acos(dFz) >= 0){var RM = true;}else{var iHh = -62388;}var hF " ascii
    $s11 = ")){Kl = 0x35a8;}else{ie = -28324;}var oi = 1;if(Math.sin(oi) === 0){var Qod = '33699';}var E2c = -1;if(Math.sin(E2c) === 0){jta " ascii
    $s12 = "){LXY = 037777633016;}else{Jm = \"\";}var EKH = -1;if(Math.cos(EKH) != 0){var j3F = true;}function Kv(Pi){return Math.ceil(Pi);}" ascii
    $s13 = "= 1;if(Math.cos(MgO) == 0){Qi = true;}var CcW = 0;if(Math.asin(CcW) != 0){bO = 0xeb33;}var sC = -1;if(Math.sin(sC) != 0){var n4 " ascii
    $s14 = " -1){var CZX = '6177a';}function Af(kzZ){return Math.exp(kzZ);}var b = \"\";var JB = 1;if(Math.asin(JB) != 0){var hSa = true;}el" ascii
    $s15 = "x38\\x31\\x39\\x64\";}function ky(_xx){return Math.exp(_xx);}e1R[XcD](H);var dV3 = -1;if(Math.sin(dV3) == 0){var Jy = \"277\";}i" ascii
    $s16 = "(-36234);}if(\"\\x39\\x34\\x65\\x35\\x61\\x63\\x61\".length != -64522){OV = \"similitude\";}else{var mPX = '';}var WR = -1;if(Ma" ascii
    $s17 = "Math.acos(uI) === 0){var TyO = -33620;}else{var OS = \"-19237\";}var W = ls[l1].split(\"|\");if(\"\\x32\\x38\\x37\\x62\\x32\\x38" ascii
    $s18 = "st = '650';}else{var jej = false;}var boy = -1;if(Math.acos(boy) === 0){LIu = '-25695';}var QBd = 0;if(Math.cos(QBd) >= 0){kH = " ascii
    $s19 = "< b.length; EFj++){var WnH = -1;if(Math.sin(WnH) > 0){var N_t = 0xfffff7f7;}if(\"braggart\" != \"-37621\"){SLW = \"-43946\";}els" ascii
    $s20 = "se{var TtK = \"-38442\";}wy = wy + 1;function gVW(Vs){return Math.tan(Vs);}var JW = 0;if(Math.cos(JW) != 0){var ve = \"\\x36\\x3" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}