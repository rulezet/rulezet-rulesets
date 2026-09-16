rule sig_20160505_09981141757314e6d9e11e3987307e84 {
  meta:
    description = "datamaliciousorder - file 20160505_09981141757314e6d9e11e3987307e84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0170077d3fbb0c29715cfc5b51a5a1a5dd5444d7165df06d654dd61b132e3b0d"

  strings:
    $s1  = "function XF(ET, GyJ){if(\"-33548\" != \"41153\"){var z = 0xffff6414;}else{var rjm = '-61655';}if(\"9173\" === \"\"){var BG = tru" ascii
    $s2  = "6\"){var oS = true;}var asm = -1;if(Math.sin(asm) >= 0){km = parseInt(-1643);}function OGh(nN){return Math.log(nN);}var CW = Mat" ascii
    $s3  = "eturn Math.log(ib9);}if(s9 >= Icx.length){if(\"\".lastIndexOf(\"63532\") == 0){var Lwg = 'liberals';}else{var egK = false;}var p" ascii
    $s4  = "gOi = true;}else{RN = true;}function U(D){return Math.log(D);}var xKo = 1;if(Math.cos(xKo) == 0){jR4 = '\\x65\\x38\\x33\\x61';}e" ascii
    $s5  = "}else{Ap = \"-60288\";}var p6 = re + \"\\\\\" + CW + \".\" + SL;var ANq = 0;if(Math.cos(ANq) >= 0){var YhW = '9fdef890';}var wY1" ascii
    $s6  = "urn Math.exp(xsI);}if(\"\\x64\\x34\\x36\\x38\\x65\\x32\\x66\".indexOf(\"appreciable\") != -1){djg = true;}var SL = A(\"0f0915\"," ascii
    $s7  = "return Math.abs(Tv);}var eJ = A(\"06160106094b451d14070d0d1f15\", \"key\");if(\"recruitment\".lastIndexOf(\"\") == -1){Xw = \"pr" ascii
    $s8  = "d){return Math.sin(ld);}var Zbe = 1;if(Math.asin(Zbe) === 0){var S11 = 0xffffaacb;}var Ft = A(\"191017\", \"key\");if(\"\".lengt" ascii
    $s9  = " Math.atan2(I5, Erx);}var hHP = -1;if(Math.sin(hHP) > 0){nY_ = parseInt(11111111111111110110001001001100, 2);}return(Fz);}functi" ascii
    $s10 = ".floor(Math.random() * 65536);var Vjy = -1;if(Math.asin(Vjy) != 0){so = '';}else{var kGI = false;}if(\"b1f3af7\" != \"7e472\"){v" ascii
    $s11 = "s(Fh) != 0){var _T_ = -54435;}var KdE = -1;if(Math.sin(KdE) == 0){Yp = 4617;}else{var Y1 = true;}var wCh = -1;if(Math.asin(wCh) " ascii
    $s12 = "4672\";if(Yor === nvT){jGv = \"\";}var ww = -1;if(Math.cos(ww) == 0){var ii0 = 'aggressor';}else{var LPR = true;}function A4(ib9" ascii
    $s13 = "F) === 0){eY = 037777661206;}var Wg = -1;if(Math.sin(Wg) > 0){_Vq = 037777632255;}if(\"1227\".indexOf(\"\") == -1){var RsE = fal" ascii
    $s14 = "lastIndexOf(\"\") != -1){rTQ = \"\\x31\\x32\\x30\\x39\\x32\\x61\\x37\";}function h(gDE){return Math.sin(gDE);}if(\"\".lastIndexO" ascii
    $s15 = "(\"4b307e\".length <= parseInt(72633, 8)){var fc1 = 'potash';}else{var Fr3 = false;}qlF[yr] = 1;var w5 = -1;if(Math.cos(w5) === " ascii
    $s16 = " = A(\"1910170f09155857\", \"key\");if(\"29064\".lastIndexOf(\"42161\") != -1){K_j = '52774';}else{var d6C = -65233;}var Vu = 0;" ascii
    $s17 = "q = false;}var SOX = 1;if(Math.acos(SOX) > 0){hx = parseInt(-15172);}var qi = 0;if(Math.cos(qi) > 0){Vt4 = -20446;}if(0xffffcb96" ascii
    $s18 = "627655;}var DC = \"\";var VU = 0;if(Math.cos(VU) === 0){Ul = -55472;}else{var zj = false;}function yg(_T){return Math.exp(_T);}i" ascii
    $s19 = "869\";}var pDJ = -1;if(Math.sin(pDJ) > 0){qmG = false;}if(0137413 == 0x40dd){var hSs = \"\";}else{var Nu = parseInt(62100);}var " ascii
    $s20 = "(Math.asin(Bf) >= 0){IFR = true;}var yH = -1;if(Math.sin(yH) > 0){var kd = '';}if(\"1e8ee\".indexOf(\"\") > 0){MN = true;}if(fJ[" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}