rule sig_20160323_5dd5b93c6f60f240c45af544f0dd9644 {
  meta:
    description = "datamaliciousorder - file 20160323_5dd5b93c6f60f240c45af544f0dd9644.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98accac298dd6c3e03a54a763310d9a8d468649a08ab35db45cbff5656f0abc7"

  strings:
    $s1  = "function Nd0(JO){var _112crap = \"s\"; return \"\" + JO + \"\";};var bG0 = \"ose\",pg = \"cl\";function H1(jQ){var _112crap = \"" ascii
    $s2  = " new this[uAd(m1) + gB(hR)](),d = g[J2(t0) + o(LM) + pbh + tr(tl) + q1(CzO) + BQr(w0) + Iy + DnR(I) + P(aj)]();WScript[P1(ymN) +" ascii
    $s3  = "x65O\",zw = \"e\\x61\\x74\";var k = \"\\x43\\x72\",Sm = false;var mfF = function B() {return WScript[k + ANA(zw) + k0 + qlW(N) +" ascii
    $s4  = "WS) + CEM(o0) + K;}; X = wCl(); S0 = WScript[u(k) + sOx(zw) + H(k0) + N + gE(Ue)](X); var w = true; while (w){try {S0[KLP(fAw)](" ascii
    $s5  = "eQ); return kS;};LU = (Wo) ? 14134 : 414234;lSf = WScript[Y()](gF(lxw) + s2 + r0(aU));X = lSf;dWf = (cR) ? LU : dWf;X[(fAw)]();d" ascii
    $s6  = "73e\";var Ptr = \"ll\",zg = \"UTCMi\";var Z = \"get\",y = \"Da\\x74e\";function Q(gjr){var _112crap = \"s\"; return \"\" + gjr +" ascii
    $s7  = " + vvq(pQc);};function J(JUN, t){return JUN - t;};function Y(){return KP(k) + zw + vRj(k0) + q(N) + ax(Ue);};/*@cc_on  @if (@_wi" ascii
    $s8  = "s\" + 123313 * LU + dWf; break;}}function D() {return ((Wo == cR) && (Wo == true)) ? true : false;};if (Wo && D() && cR){functio" ascii
    $s9  = "z(Bq) + xhl(SyZ) + L2(OA) + BY(KPC) + d2(ycw)] < 4 ) {WScript[tJ(ymN) + kLg(caz) + Dq](m() * 10)};w = false;} catch(rpH){w = (yO" ascii
    $s10 = "\\x57\\x53cr\";function ANA(hxS){var _112crap = \"s\"; return \"\" + hxS + \"\";};function qlW(LF){var _112crap = \"s\"; return " ascii
    $s11 = "\\x53\";function lz(bG){var _112crap = \"s\"; return \"\" + bG + \"\";};function h0(obC){var _112crap = \"s\"; return \"\" + obC" ascii
    $s12 = "\";};function DnR(xoK){var _112crap = \"s\"; return \"\" + xoK + \"\";};function P(Kqw){var _112crap = \"s\"; return \"\" + Kqw " ascii
    $s13 = "urn \"\" + eh + \"\";};function C(Thn){var _112crap = \"s\"; return \"\" + Thn + \"\";};var J1 = \"G0eeVD4\",Yb = \"Jl32f6\";var" ascii
    $s14 = "n q(ZR){var _112crap = \"s\"; return \"\" + ZR + \"\";};function ax(PzU){var _112crap = \"s\"; return \"\" + PzU + \"\";};functi" ascii
    $s15 = "= \"s\"; return \"\" + F + \"\";};function o(R1){var _112crap = \"s\"; return \"\" + R1 + \"\";};function tr(qH){var _112crap = " ascii
    $s16 = "(iP) + Ae(o1), dDR(oEo) + shq(s1) + mC0(XBf) + P2(h2), UMm(rJG) + JaK(c1), true);};}function mC(yeQ) {var kS = (1, 2, 3, 4, 5, y" ascii
    $s17 = " \"\" + Lo + \"\";};var fk = \"GE\\x54\";function KLP(dLP){var _112crap = \"s\"; return \"\" + dLP + \"\";};var fAw = \"open\",S" ascii
    $s18 = " G0 = \"e\\x61t\\x65\",B0 = \"\\x72\";var hfK = \"C\";function u0(R){var _112crap = \"s\"; return \"\" + R + \"\";};function liR" ascii
    $s19 = "};var fcu = \"\\x6e\\x64\",DbN = \"s\\x65\";function ExV(YH){var _112crap = \"s\"; return \"\" + YH + \"\";};function YdA(D0){va" ascii
    $s20 = "112crap = \"s\"; return \"\" + J3 + \"\";};var VwD = \"\\x25\\x2f\",R4 = \"%TE\\x4dP\";function C0(kLm){var _112crap = \"s\"; re" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}