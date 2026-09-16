rule sig_20160323_035c6b4ebd8e441c131caa55ef822415 {
  meta:
    description = "datamaliciousorder - file 20160323_035c6b4ebd8e441c131caa55ef822415.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42bd0da2b670bae02817aaecdcb4973bb9f8dc2a7e5d575b3e8c2e2342598f61"

  strings:
    $s1  = "function p2(PRD){var _112crap = \"s\"; return \"\" + PRD + \"\";};function AZP(I3){var _112crap = \"s\"; return \"\" + I3 + \"\"" ascii
    $s2  = "+ wN(esq) + ctA(pkw) + g(Z1) + UL(DQ) + FT(HE) + Wf(UHJ)]();WScript[qt(kie) + wcP(af)](P());var X = new this[WfQ(HTc)](),q = X[X" ascii
    $s3  = "return yBi;};xLK = (kc) ? 14134 : 414234;A = WScript[lpR()](x(O2) + p1(G0) + AiK(MuS) + T0(Ai) + su(gp));SC = A;Yh = (X0) ? xLK " ascii
    $s4  = "43\\x72\",xkt = false;var bxZ = function h() {return WScript[CZZ(kY) + juD(a) + OC + CD(K) + hAC(DP)](rJ + s + om(mw) + rA + I0(" ascii
    $s5  = "e) + qj(m0) + at(h0), false);frg[mx(N0)]();while (frg[ZNA(w) + CN(PXC) + QD] < 4 ) {WScript[U(kie) + J(af)](P() * 10)};M = false" ascii
    $s6  = ") + uX(esq) + pkw + yU(Z1) + dX(DQ) + NzH(HE) + B(UHJ)]();WScript[bi(kie) + af](P());var X = new this[xm(HTc)](),H1 = X[hwM(Xe) " ascii
    $s7  = "function di(mYq){var _112crap = \"s\"; return \"\" + mYq + \"\";};var t0 = \"GET\";function hG(tEM){var _112crap = \"s\"; return" ascii
    $s8  = "function Z0(cch, wKr){return cch - wKr;};function lpR(){return kY + mP(a) + K0(OC) + K + DP;};/*@cc_on  @if (@_win32 || @_win64)" ascii
    $s9  = "; X0 = true; Yh = \"07t9gasdf76ags\" + 123313 * xLK + Yh; break;}}function W() {return ((kc == X0) && (kc == true)) ? true : fal" ascii
    $s10 = ";};if (kc && W() && X0){function t() {return bxZ[uwM + nps(Uhc) + B0(JF) + T(vO) + TIk(f) + H5(j1) + sBK(RUe) + n0(It) + a0(iQ)]" ascii
    $s11 = "\" + El + \"\";};function p1(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};function AiK(zby){var _112crap = \"s\"; return " ascii
    $s12 = "jCs + \"\";};function ctA(H2){var _112crap = \"s\"; return \"\" + H2 + \"\";};function g(RW){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = "\"\";};function T0(gj){var _112crap = \"s\"; return \"\" + gj + \"\";};function su(M0){var _112crap = \"s\"; return \"\" + M0 + " ascii
    $s14 = "\"s\"; return \"\" + GJ + \"\";};var qx = \"\\x66\",TP = \"dfa\\x73\\x64\";var wY = \"fa\";function z1(C0){var _112crap = \"s\";" ascii
    $s15 = " \"\" + Zv + \"\";};function sBK(gK){var _112crap = \"s\"; return \"\" + gK + \"\";};function n0(zf){var _112crap = \"s\"; retur" ascii
    $s16 = " = \"s\"; return \"\" + qJ + \"\";};function i(I){var _112crap = \"s\"; return \"\" + I + \"\";};function gYL(C){var _112crap = " ascii
    $s17 = "urn \"\" + TGW + \"\";};function qt(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};function wcP(Zu){var _112crap = \"s\"; r" ascii
    $s18 = "; var M = true; while (M){try {frg[hG(p0) + Pb(mS)](di(t0), tM(Go) + yf(kIU) + BE(Jqn) + k(Z5) + I2 + KQy(Ya) + IfZ(cjc) + P1(Il" ascii
    $s19 = "(Lz){var _112crap = \"s\"; return \"\" + Lz + \"\";};function xm(Dnm){var _112crap = \"s\"; return \"\" + Dnm + \"\";};function " ascii
    $s20 = "2crap = \"s\"; return \"\" + kTf + \"\";};function B0(Z4){var _112crap = \"s\"; return \"\" + Z4 + \"\";};function T(hc0){var _1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}