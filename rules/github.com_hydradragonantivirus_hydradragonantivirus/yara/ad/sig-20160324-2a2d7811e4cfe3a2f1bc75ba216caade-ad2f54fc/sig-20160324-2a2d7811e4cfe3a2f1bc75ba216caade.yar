rule sig_20160324_2a2d7811e4cfe3a2f1bc75ba216caade {
  meta:
    description = "datamaliciousorder - file 20160324_2a2d7811e4cfe3a2f1bc75ba216caade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5979ca70af02b4706d93a91bb7c5a6bee65f4e8a7dc97046823e53014e96cdde"

  strings:
    $s1  = "var vN = \"cl\\x6fse\";function CC(aHJ){var _112crap = \"s\"; return \"\" + aHJ + \"\";};var HqO = \"\\x65\",iQ = \"\\x54oF\\x69" ascii
    $s2  = "tion FO(){return 22;};var e0 = 0,A = 0;function g(){var YxN = new this[x(gFk)](),AE = YxN[PSH + D0 + W + Drs]();WScript[gfz](FO(" ascii
    $s3  = "));var YxN = new this[gFk](),DW = YxN[PSH + zZi(D0) + W + U(Drs)]();WScript[gfz](FO());var YxN = new this[V(gFk)](),y0 = YxN[PSH" ascii
    $s4  = "Obj\\x65\";var u = \"Cre\\x61t\",nNz = false;var D = \"CreateObject\",zql = function y() {return WScript[D](a + OT + cgt(n) + Sp" ascii
    $s5  = "{S = (Np, aJ0 + G, L0 + ngM(n0), 2);};}function vF(e) {var BV = (1, 2, 3, 4, 5, e); return BV;};E = WScript[FX()](Feg + u0 + h1)" ascii
    $s6  = "zql[yoQ + pU + t + yL + Lp(qou)](pg + j) + Z0 + oWw + NUd;}; xv = Z(); w = WScript[D](xv); var S = 1; while (S){try {w[VH](Du(mD" ascii
    $s7  = "unction U(h0){var _112crap = \"s\"; return \"\" + h0 + \"\";};var Drs = \"ond\\x73\",W = \"is\\x65c\";var D0 = \"C\\x4d\\x69\\x6" ascii
    $s8  = "313 * e0 + A; break;}}function DHc() {return ((RV == true) && (RV == X)) ? 1 : R;};if (RV && DHc() && X){function BlY() {return " ascii
    $s9  = "), qHA + s + Fm + S0 + pb + XdP, false);w[H]();m = \"Sleep\";while (w[j0 + Vk + i0] < 4 ) {WScript[m](FO() * 10)};S = R;} catch(" ascii
    $s10 = "\",XdP = \"u\\x78j2\";var pb = \"\\x6fm/m4\",S0 = \"ra\\x2ec\";var Fm = \"e\\x78ce\",s = \"\\x2f\\x2fpl\";var qHA = \"h\\x74\\x7" ascii
    $s11 = "x54\";function x(bYB){var _112crap = \"s\"; return \"\" + bYB + \"\";};function V(Om){var _112crap = \"s\"; return \"\" + Om + " ascii
    $s12 = " + D0 + W + Drs]();var e0 = \"aJ\";e0 = Q(DW, AE);var A = \"Hw\";A = Q(y0, DW);return Q(e0, A);}var RV = false,X = false;for (va" ascii
    $s13 = "var _112crap = \"s\"; return \"\" + L + \"\";};var mD = \"GE\\x54\",VH = \"o\\x70en\";var NUd = \"\\x65x\\x65\",oWw = \"M4x\\x2e" ascii
    $s14 = "av\\x65\";function v0(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};var Znw = \"ti\\x6fn\",s0 = \"p\\x6f\\x73i\";var qY = " ascii
    $s15 = "x43\\x4dill\",w0 = \"\\x67etUT\";var VG = \"\\x44\\x61te\",gfz = \"Sl\\x65\\x65p\";function zZi(K){var _112crap = \"s\"; return " ascii
    $s16 = "var vN = \"cl\\x6fse\";function CC(aHJ){var _112crap = \"s\"; return \"\" + aHJ + \"\";};var HqO = \"\\x65\",iQ = \"\\x54oF\\x69" ascii
    $s17 = "xC\",j = \"P%\\x2f\";var pg = \"%\\x54EM\";function Lp(kJ){var _112crap = \"s\"; return \"\" + kJ + \"\";};var qou = \"r\\x69ngs" ascii
    $s18 = "p = \"s\"; return \"\" + Ka + \"\";};var Sp = \"\\x6c\",n = \"Sh\\x65\\x6c\";var OT = \"i\\x70\\x74.\",a = \"\\x57Scr\";var SKY " ascii
    $s19 = " = R; NF < FO() * 1; NF++){if (g() != R){RV = true; A = \"07t9gasdf76ags\" + 123313 * e0 + A; X = true; A = \"07t9gasdf76ags\" +" ascii
    $s20 = "\";function ngM(QrJ){var _112crap = \"s\"; return \"\" + QrJ + \"\";};var n0 = \"\\x66a\",L0 = \"\\x61\\x66da\";var G = \"s\\x64" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}