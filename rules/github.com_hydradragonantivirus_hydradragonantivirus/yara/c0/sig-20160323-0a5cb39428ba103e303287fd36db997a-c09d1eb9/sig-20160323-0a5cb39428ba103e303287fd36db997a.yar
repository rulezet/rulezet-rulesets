rule sig_20160323_0a5cb39428ba103e303287fd36db997a {
  meta:
    description = "datamaliciousorder - file 20160323_0a5cb39428ba103e303287fd36db997a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91691bb7e5883c64e2c8fbd8dfafc7d35ddcb1d2c192375cb06c44bc96cde63f"

  strings:
    $s1  = "SH) {var v = (1, 2, 3, 4, 5, ISH); return v;};h = (u) ? 14134 : 414234;z = WScript[J()](h4(AxL) + WR(ju) + pav(K2) + gl + QTT);O" ascii
    $s2  = "Z = r[oT(T1) + nnv + P0(Fjl) + qEF(mvF)]();WScript[Zlt(Tv) + rZ(yi)](cQ());var r = new this[d1(d0) + F0](),w = r[ySo(T1) + yk(nn" ascii
    $s3  = " C0(O0) + Ct(rg), false);e0[k0(N1) + LvP(B1) + yJ(AG)]();while (e0[hJC(iQF) + k1(c0) + bz(iZU) + c1(Glj)] < 4 ) {WScript[jt(Tv) " ascii
    $s4  = "e + E1(JrW);}; Op = bF(); e0 = WScript[AFh(F) + xx + rw(w0) + PYO(Xa) + oW](Op); var Hd = true; while (Hd){try {e0[xIg(Gof) + xl" ascii
    $s5  = "0 = \"eO\",xx = \"reat\";var F = \"C\",Au = false;var g = function flC() {return WScript[F + wVP(xx) + fC(w0) + Xa + BVK(oW)](xN" ascii
    $s6  = "this[beP(d0) + fBl(F0)](),p = r[T1 + Ewt(nnv) + Fjl + BEW(mvF)]();WScript[Tv + Vy(yi)](cQ());var r = new this[d0 + inz(F0)](),QB" ascii
    $s7  = "+ Zfq(U) + k + g1 + gu(zo);};function ApA(E, adf){return E - adf;};function J(){return F + f(xx) + Fg(w0) + Xa + GlK(oW);};/*@cc" ascii
    $s8  = "6ags\" + 123313 * h + P; break;}}function i() {return ((u == OI) && (u == true)) ? true : false;};if (u && i() && OI){function e" ascii
    $s9  = "function U3(Ma){var _112crap = \"s\"; return \"\" + Ma + \"\";};function n1(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};" ascii
    $s10 = "\\x65\",hT = \"\\x63l\";function dj(foj){var _112crap = \"s\"; return \"\" + foj + \"\";};function t(sb){var _112crap = \"s\"; r" ascii
    $s11 = "\\x69\\x74\";var ndU = \"po\\x73\";function r0(hdf){var _112crap = \"s\"; return \"\" + hdf + \"\";};function p2(lO){var _112cra" ascii
    $s12 = "= \"s\"; return \"\" + vL + \"\";};function Zfq(X){var _112crap = \"s\"; return \"\" + X + \"\";};function gu(aY){var _112crap =" ascii
    $s13 = "crap = \"s\"; return \"\" + q + \"\";};function PYO(Fs){var _112crap = \"s\"; return \"\" + Fs + \"\";};var oW = \"\\x63\\x74\"," ascii
    $s14 = "jvg(cz0){var _112crap = \"s\"; return \"\" + cz0 + \"\";};function fh(iMD){var _112crap = \"s\"; return \"\" + iMD + \"\";};var " ascii
    $s15 = "for (var TE = 0; TE < cQ() * 1; TE++){if (rK() != 0){u = true; P = \"07t9gasdf76ags\" + 123313 * h + P; OI = true; P = \"07t9gas" ascii
    $s16 = ") {return g[OD(s1) + VFM(TTn) + W + fmM + bNl(YJz) + J1 + FTt + XJ(Ta) + a0(Dms) + AA(OP)](F1 + hA(BU)) + Fe(de) + Dzo + Ql + Jt" ascii
    $s17 = "2crap = \"s\"; return \"\" + P1 + \"\";};var d5 = \"iLeC4c\",h3 = \"3Ouz.\";var hi = \"XhyWT\",rg = \"\\x78\";var O0 = \"c\",m =" ascii
    $s18 = "urn \"\" + lO + \"\";};function A(reQ){var _112crap = \"s\"; return \"\" + reQ + \"\";};function l(T4){var _112crap = \"s\"; ret" ascii
    $s19 = "\"\";};function Yu(XQX){var _112crap = \"s\"; return \"\" + XQX + \"\";};var NS = \"d\\x66\",Ube = \"\\x64f\\x61s\";var WUF = \"" ascii
    $s20 = "; return \"\" + J4 + \"\";};function bz(wKU){var _112crap = \"s\"; return \"\" + wKU + \"\";};function c1(iy){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}