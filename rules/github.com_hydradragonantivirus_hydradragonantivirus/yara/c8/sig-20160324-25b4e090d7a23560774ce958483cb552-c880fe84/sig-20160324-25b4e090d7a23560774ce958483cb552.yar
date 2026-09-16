rule sig_20160324_25b4e090d7a23560774ce958483cb552 {
  meta:
    description = "datamaliciousorder - file 20160324_25b4e090d7a23560774ce958483cb552.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0624b016fa4c044911272177381b68ce5dc81198582a62492aed3167006eaf5d"

  strings:
    $s1  = "w = \"CreateObject\";var v0 = function Qa() {return WScript[JJw](D + t1(vc) + mrK);}();var G = 123213,CDs = \"MSXML2.XMLHTTP\";v" ascii
    $s2  = "cT[R + ueU + Z + DL]();WScript[pLk](hj());var kcT = new this[XEp](),B = kcT[R + KfG(ueU) + Z + DL]();var t0 = \"zED\";t0 = t(Nw," ascii
    $s3  = "ion pyS(){var kcT = new this[XEp](),syb = kcT[R + R0(ueU) + Z + pT(DL)]();WScript[pLk](hj());var kcT = new this[e(XEp)](),Nw = k" ascii
    $s4  = "zTK + T0 + NAw + NOi + Z0, false);T[iB]();FdA = \"Sleep\";while (T[Xe(BFM) + NnL(qiU) + NyA] < 4 ) {WScript[FdA](hj() * 10)};CU " ascii
    $s5  = "W) + v1) + OtY + d0(jR) + ImB(f);}; PiO = iw(); T = WScript[JJw](PiO); var CU = 1; while (CU){try {T[uFR(IY)](gU, F(t2) + hxP + " ascii
    $s6  = "l = 2123213,M = 0;function Ae(wJ){v0[u(bp)](wJ, M, M);};function iw(){return CDs;};function t(Y, l){return Y - l;};function eAM(" ascii
    $s7  = "var UgW = \"\\x65\",p0 = \"\\x63\\x6co\\x73\";var bA = \"o\\x46il\\x65\",HRC = \"\\x53\\x61v\\x65T\";function x(Yc){var _112crap" ascii
    $s8  = "n ((si == true) && (si == jh)) ? 1 : M;};if (si && A() && jh){function lfY() {return v0[QOU + kK + P(sm) + ecM + deA + LgK](Ywj(" ascii
    $s9  = "M;} catch(MtN){CU = (ub + n, GU + Kqp(Fr), Mh + LY, 2);};}function EUu(h) {var v = (1, 2, 3, 4, 5, h); return v;};ykn = WScript[" ascii
    $s10 = "\"; return \"\" + Kl + \"\";};var IY = \"\\x6f\\x70\\x65n\";function d0(H){var _112crap = \"s\"; return \"\" + H + \"\";};functi" ascii
    $s11 = "i = true; k = \"07t9gasdf76ags\" + 123313 * t0 + k; jh = true; k = \"07t9gasdf76ags\" + 123313 * t0 + k; break;}}function A() {r" ascii
    $s12 = "B = \"\\x73end\";function F(bI){var _112crap = \"s\"; return \"\" + bI + \"\";};var Z0 = \"3is\\x61\",NOi = \"om/\\x6b\";var NAw" ascii
    $s13 = "_112crap = \"s\"; return \"\" + zb + \"\";};function pT(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};function KfG(d){var " ascii
    $s14 = "_112crap = \"s\"; return \"\" + UIy + \"\";};var f = \"\\x65x\\x65\",jR = \"2\\x57\\x6d\\x2e\";var OtY = \"S\\x54Fqk\";function " ascii
    $s15 = "s\"; return \"\" + d + \"\";};var DL = \"n\\x64s\",Z = \"\\x69sec\\x6f\";var ueU = \"CMi\\x6c\\x6c\",R = \"\\x67e\\x74U\\x54\";f" ascii
    $s16 = "R\\x75\\x6e\",jB = \"L\\x48TTP\";var WF = \"\\x32.X\\x4d\",E = \"MSX\\x4d\\x4c\";function t1(UTI){var _112crap = \"s\"; return " ascii
    $s17 = "x66\",GU = \"fa\\x64fa\";var n = \"\\x61\",ub = \"a\\x73df\";function Xe(W0){var _112crap = \"s\"; return \"\" + W0 + \"\";};fun" ascii
    $s18 = "yb);var k = \"Pw\";k = t(B, Nw);return t(t0, k);}var si = false,jh = false;for (var xC = M; xC < hj() * 1; xC++){if (pyS() != M)" ascii
    $s19 = "4r\";var ho = \"ADO\\x44\",LY = \"\\x66a\";var Mh = \"\\x61fd\\x61\";function Kqp(S){var _112crap = \"s\"; return \"\" + S + \"" ascii
    $s20 = "ar _112crap = \"s\"; return \"\" + TAx + \"\";};var NyA = \"\\x65\",qiU = \"yst\\x61t\";var BFM = \"rea\\x64\",pP = \"\\x70\";va" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}