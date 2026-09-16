rule sig_20160505_4f9616a7d9abbb8fefe11e29eae488d5 {
  meta:
    description = "datamaliciousorder - file 20160505_4f9616a7d9abbb8fefe11e29eae488d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9e58e2559979738063a5f247ee72c332a8cb2ed9ce2b4bc987fc64ce4177a75"

  strings:
    $x1  = "function UQs(Z){if(parseInt(11111111111111110100100001011010, 2) <= -35752){TLm = \"a398c\";}else{QH = parseInt(13351);}function" ascii
    $s2  = "th.asin(GKX) != 0){TIl = \"12455\";}function Zn(EhK){return Math.log(EhK);}var a_r = -1;if(Math.cos(a_r) === 0){Ic = false;}else" ascii
    $s3  = "r P = rN(i28);function ce2(X3S){return Math.log(X3S);}if(0xfffff854 > 39387){QX = false;}else{uD = -47504;}var tv2 = 1;if(Math.a" ascii
    $s4  = "8);}function g6s(zSz){return Math.log(zSz);}Fj[pSt]();var lv = -1;if(Math.asin(lv) >= 0){kY = -35387;}var bd = 0;if(Math.sin(bd)" ascii
    $s5  = "}Fj[j2U]();function QqK(AP){return Math.log(AP);}function eb(Mn){return Math.atan(Mn);}if(\"-2897\".lastIndexOf(\"-8131\") < 0){" ascii
    $s6  = "= true;}var kNi = -1;if(Math.cos(kNi) != 0){vl = '-24695';}else{var eN = parseInt(152043, 8);}Y = Y + 1;var Ep = -1;if(Math.asin" ascii
    $s7  = "10170f09155857\", \"key\");if(\"38969\".length == -5901){var Mu = '89d3f7e4';}function DD(lRX){return Math.cos(lRX);}var GoF = -" ascii
    $s8  = "328';}if(\"circumstances\".length <= parseInt(11111111111111111111111011000100, 2)){xvw = false;}var tP = 0;if(Math.cos(tP) >= 0" ascii
    $s9  = "}var ZBC = -1;if(Math.sin(ZBC) === 0){Kw = false;}else{var DGU = \"-64191\";}var BIx = Wi(\"1811181f100a\", \"key\");var GKX = 0" ascii
    $s10 = " = -1;if(Math.acos(VU) > 0){npF = \"41287\";}else{tN = 53166;}function gNy(KS){return Math.tan(KS);}if(\"identifier\".length >= " ascii
    $s11 = "011101001, 2)){var tw = -13775;}var NQ = 0;if(Math.sin(NQ) === 0){var gw = parseInt(11111111111111110001100100100101, 2);}else{q" ascii
    $s12 = "arseInt(11111111111111110110000111101101, 2);}if(\"-17809\".length != -3082){var pN = false;}var NDU = -1;if(Math.cos(NDU) > 0){" ascii
    $s13 = "ar s = -1;if(Math.asin(s) != 0){YC = true;}var M = -1;if(Math.sin(M) >= 0){j3 = 0x6850;}else{var uT = false;}DC += String.fromCh" ascii
    $s14 = "495);}if(\"working\".indexOf(\"\") == 0){BU = -65313;}function Xgo(P1B){return Math.acos(P1B);}var MV = Wi(\"0e1d1c\", \"key\");" ascii
    $s15 = "th.acos(hx) > 0){hs = false;}if(D[HNa] == 1){function c6p(ql){return Math.tan(ql);}if(0xaa86 != -62266){c_h = 016305;}if(-18364 " ascii
    $s16 = "jK = -1;if(Math.sin(jK) > 0){var CpV = 0xffff1a7b;}else{var tT = \"3abe\";}var kT = 1;if(Math.cos(kT) != 0){BIR = true;}else{var" ascii
    $s17 = "Math.round(kw);}for(var WFF = 0; WFF < Z.length; WFF += 2){if(parseInt(11001011111000, 2) == 0xb865){var K = '';}else{OE8 = -387" ascii
    $s18 = "bbd89e\".length >= 0xffff9f69){Bab = \"e020e143\";}var dgI = 1;if(Math.cos(dgI) >= 0){Yd = false;}var BGr = -1;if(Math.asin(BGr)" ascii
    $s19 = "ikewise\") == 0){f0 = -40703;}function P1p(e){return Math.exp(e);}if(\"-63369\".lastIndexOf(\"-37740\") < 0){J = parseInt(170012" ascii
    $s20 = "(Math.sin(qpt) != 0){_wk = 0xffffc48f;}var oy = -1;if(Math.cos(oy) != 0){Xa = '';}var qc = 1;if(Math.sin(qc) == 0){k_c = false;}" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}