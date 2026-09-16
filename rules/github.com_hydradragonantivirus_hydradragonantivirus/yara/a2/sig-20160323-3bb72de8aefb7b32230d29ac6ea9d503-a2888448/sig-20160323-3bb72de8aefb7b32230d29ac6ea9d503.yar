rule sig_20160323_3bb72de8aefb7b32230d29ac6ea9d503 {
  meta:
    description = "datamaliciousorder - file 20160323_3bb72de8aefb7b32230d29ac6ea9d503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96db65f305c650503b56c284deb4b4397620980fbb2cd362d82a140bcd9126e1"

  strings:
    $s1  = "var aos = \"ose\",Bd = \"\\x63l\";function gqr(nY){var _112crap = \"s\"; return \"\" + nY + \"\";};function Ax(qaP){var _112crap" ascii
    $s2  = "\"L3m\";var f0 = \"5M\\x4fv\";function uT(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};var f = \"%/\",T = \"%TEMP\";funct" ascii
    $s3  = "(W0) + L0(SUz)](),q = m[Xkr(IcW) + nk(vIm) + wz(ry) + bh + X1(FLP) + Sm(fNa)]();WScript[pI(S0) + Vt](FJx());var m = new this[Ys(" ascii
    $s4  = "SU(W0) + bP(SUz)](),X = m[bja(IcW) + pD(vIm) + ry + Z(bh) + rx(FLP) + g(fNa)]();WScript[Ns(S0) + Vt](FJx());var m = new this[waj" ascii
    $s5  = "x74\";var kh = Wu[\"\"+\"\\x63\"+\"ha\"+\"\\x72\"+\"At\"](4),z = false;var w0 = function c() {return WScript[r(kh) + pG(nBt) + C" ascii
    $s6  = " BK + jVi + gIZ + V0 + XIR(q1) + wc(GRN), false);fA[qTo(sM)]();while (fA[E(BG) + j4(lFR) + yuW(AB) + y2(Tp)] < 4 ) {WScript[h0(S" ascii
    $s7  = "S(ttP) + SwI(To) + eG(j1);};function l0(pn, rmX){return pn - rmX;};function a(){return Zpt(kh) + nBt + cI + Lp(Jsh);};/*@cc_on  " ascii
    $s8  = " true)) ? true : false;};if (Q && w() && nq){function h() {return w0[F + G0(PQk) + QFU + cXr(h2) + fjZ + hw(h3) + btP(mZX) + p0 " ascii
    $s9  = "76ags\" + 123313 * sj + j0; nq = true; j0 = \"07t9gasdf76ags\" + 123313 * sj + j0; break;}}function w() {return ((Q == nq) && (Q" ascii
    $s10 = "Dl), true);};}function Qw(vac) {var zj = (1, 2, 3, 4, 5, vac); return zj;};sj = (Q) ? 14134 : 414234;sWU = WScript[a()](ps(a1) +" ascii
    $s11 = "+\"\\x63\"+\"ha\"+\"\\x72\"+\"At\"](3);var FLP = \"nd\",bh = \"\\x65c\\x6f\";var ry = \"lli\\x73\",vIm = \"T\\x43M\\x69\";var Ic" ascii
    $s12 = "\\x72\"+\"At\"](2),Al = \"Cre\";function QK(CU){var _112crap = \"s\"; return \"\" + CU + \"\";};function xDQ(Fp){var _112crap = " ascii
    $s13 = "\";};function S4(j5){var _112crap = \"s\"; return \"\" + j5 + \"\";};var x0 = \"io\\x6e\",YL = \"posit\";function qT(xM){var _11" ascii
    $s14 = "J, q);return l0(sj, j0);}var Q = false,nq = false;for (var kR = 0; kR < FJx() * 1; kR++){if (l() != 0){Q = true; j0 = \"07t9gasd" ascii
    $s15 = " g0 + \"\";};function zRH(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function XIR(fdh){var _112crap = \"s\"; return \"\" " ascii
    $s16 = "Eq){var _112crap = \"s\"; return \"\" + Eq + \"\";};function bP(itk){var _112crap = \"s\"; return \"\" + itk + \"\";};function w" ascii
    $s17 = "p = \"s\"; return \"\" + Q1 + \"\";};function Iuo(T2){var _112crap = \"s\"; return \"\" + T2 + \"\";};var h4 = \"haYyzxh\",L2 = " ascii
    $s18 = "rap = \"s\"; return \"\" + JJ + \"\";};var ZJ0 = \"ulyte461pS\",L3 = ZJ0[\"\"+\"\\x63\"+\"ha\"+\"\\x72\"+\"At\"](4);var QDY = \"" ascii
    $s19 = " _112crap = \"s\"; return \"\" + TmB + \"\";};function pI(giF){var _112crap = \"s\"; return \"\" + giF + \"\";};function h0(fws)" ascii
    $s20 = ")](FU(q0) + gLR(U) + Dp + bT + W);}();function Usa(mpo){w0[UdF](mpo, 0, 0);};function kES(){return mP(YF) + xt(QG) + VaA(PpS) + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}