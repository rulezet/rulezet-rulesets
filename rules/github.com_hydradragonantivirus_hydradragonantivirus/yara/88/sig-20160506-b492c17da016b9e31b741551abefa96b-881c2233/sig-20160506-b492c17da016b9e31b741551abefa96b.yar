rule sig_20160506_b492c17da016b9e31b741551abefa96b {
  meta:
    description = "datamaliciousorder - file 20160506_b492c17da016b9e31b741551abefa96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9ec8a0bb324e21cc92b62edbb986148f2cc1c60d14f443099ddbb77beb66a4a"

  strings:
    $s1  = "function a(Icx, s9){var Jrc = -1;if(Math.acos(Jrc) == 0){var IXI = '\\x30\\x62\\x36\\x38';}if(\"c9d7e\".length != 48098){var um9" ascii
    $s2  = " = -1;if(Math.sin(MdA) >= 0){var mHE = \"technologies\";}else{var Sl = -31706;}var hHj = -1;if(Math.acos(hHj) != 0){var rnz = fa" ascii
    $s3  = "30\\x63\\x34\\x61\\x37\\x62';}var lj = \"e2cb74d\";if(lj === \"39685\"){EF = true;}function FKn(oqj){return Math.log(oqj);}var d" ascii
    $s4  = ");}else{var CLe = \"028d0a\";}function ZY(_ow){return Math.log(_ow);}var re = a(\"1b3039100e\", \"lBPdk0WO\");if(-41780 == parse" ascii
    $s5  = "Math.asin(G) > 0){var Bax = 0171144;}else{avq = 25560;}var YXe = -1;if(Math.cos(YXe) > 0){B = -63465;}else{w = '-45285';}var WFF" ascii
    $s6  = " == -40782){sA = \"d76fd0\";}var kE = 1;if(Math.sin(kE) > 0){Px = false;}else{W4 = 59598;}var kc = parseInt(MJ[2]);function NJ(Z" ascii
    $s7  = "nction m3i(th){return Math.tan(th);}var L1Z = -1;if(Math.asin(L1Z) >= 0){var YV = \"\";}if(parseInt(-65413) === -33989){var wLJ " ascii
    $s8  = "lse{var JO5 = false;}var Xt = -1;if(Math.sin(Xt) === 0){var UQq = true;}else{var ew = '-11625';}var gn3 = \"\";var P6z = \"\";if" ascii
    $s9  = "{QXW = parseInt(37777643754, 8);}else{var nq = true;}var yVN = -1;if(Math.sin(yVN) >= 0){wAx = '9d6a5';}if(parseInt(-52501) != 0" ascii
    $s10 = "7676547;}else{RR = \"\";}if(37851 > -47455){XJc = false;}var QRd = 1;if(Math.sin(QRd) > 0){wFP = '38320d1a';}else{var CK = 52369" ascii
    $s11 = "89156\";}else{mu = \"\\x61\\x32\\x62\\x66\\x31\\x31\\x61\\x35\";}return(c5v);}function GyJ(DAW, y){var Dp = 0;if(Math.cos(Dp) ==" ascii
    $s12 = "deAt(Fz) ^ s9.charCodeAt(R));var tIL = -1;if(Math.sin(tIL) != 0){psV = '-16866';}else{O1 = \"\\x30\\x32\\x35\\x31\\x61\\x31\\x35" ascii
    $s13 = ") >= 0){var oB = 'c22446';}else{ahF = 037777603711;}var Tm = 1;if(Math.sin(Tm) > 0){VZg = -13728;}function vXm(UAC){return Math." ascii
    $s14 = " rD(rl, Gd){return Math.atan2(rl, Gd);}var dUO = 0;if(Math.sin(dUO) >= 0){var Dv = 0xffff9cb4;}cZo[Mf](Z + \" \" + d + \" \" + P" ascii
    $s15 = "025\";if(Tbf != uX){VM = 'f3c4d';}else{var f1e = parseInt(11784);}var jcy = -1;if(Math.cos(jcy) != 0){var akt = 'df8a6aa';}var d" ascii
    $s16 = "t(37777652356, 8)){var nc = -25279;}else{var JCc = 'cf1420a1';}var K7b = -1;if(Math.sin(K7b) === 0){var pn = '\\x32\\x37\\x37\\x" ascii
    $s17 = "(Math.cos(HPS) >= 0){d2k = true;}Ii[Ft](d);if(\"sticks\".lastIndexOf(\"dissent\") != -1){LK = '-9251';}var BpU = -1;if(Math.acos" ascii
    $s18 = "8\\x66\\x31\\x39\\x33\\x38\\x33\\x36\") < 0){aY = \"-2805\";}else{var LFv = 'preservation';}var N4c = -1;if(Math.cos(N4c) >= 0){" ascii
    $s19 = "== 0){var gk = \"4e883c7d\";}else{mW = \"15011\";}var eS = 0;if(Math.cos(eS) != 0){var bsl = \"e0c79\";}if(57113 < 34098){bu = -" ascii
    $s20 = " 28113){var zS = true;}var vy = 1;if(Math.asin(vy) >= 0){var Nt = '\\x32\\x66\\x38\\x30\\x33\\x64';}var jyd = -1;if(Math.cos(jyd" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}