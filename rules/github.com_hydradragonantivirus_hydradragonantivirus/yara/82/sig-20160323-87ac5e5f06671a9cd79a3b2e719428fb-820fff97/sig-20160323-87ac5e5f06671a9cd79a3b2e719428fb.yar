rule sig_20160323_87ac5e5f06671a9cd79a3b2e719428fb {
  meta:
    description = "datamaliciousorder - file 20160323_87ac5e5f06671a9cd79a3b2e719428fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0fcafd22daaaada611399ec9cb0839eab427448b3b308734fe9a3469adff5b"

  strings:
    $s1  = "function dhV(Zyr){var _112crap = \"s\"; return \"\" + Zyr + \"\";};function q2(x0){var _112crap = \"s\"; return \"\" + x0 + \"\"" ascii
    $s2  = "2eat\\x65\";var WW = \"C\",u = false;var O = function jzX() {return WScript[WW + w(SPA) + eM(X0) + gUz(R0) + Nn(NQ) + O0](v0(yW)" ascii
    $s3  = "pw(wfc)](),Z = R[N0(eqd) + bkG(i3) + l(VO) + gc + X1(wNC) + qd(OMv)]();WScript[pP(Ce)](On());var R = new this[If(i2) + MT(wfc)](" ascii
    $s4  = " return NM;};X = (x) ? 14134 : 414234;Uw = WScript[yqj()](Js(uKc) + kzA(t1) + q0 + rXp(X2));vf = Uw;Fnj = (yio) ? X : Fnj;vf[(g1" ascii
    $s5  = "),Yf = R[eqd + i3 + iGg(VO) + f(gc) + QBj(wNC) + OMv]();WScript[V(Ce)](On());var R = new this[Ge(i2) + Ih(wfc)](),GV = R[KC(eqd)" ascii
    $s6  = "\",L0 = \"con\";var xhT = \"l\\x6ci\\x73e\",Lwt = SC[\"c\"+\"\\x68\"+\"arAt\"](0);var FK = \"TCM\",jkL = \"getU\";var SI = \"\\x" ascii
    $s7  = "v2(w1) + Pi + d0 + jX(uv), false);D[l0(i4)]();while (D[aQY(TAd) + w2 + M(G) + eP + Rq] < 4 ) {WScript[e(Ce)](On() * 10)};mRh = f" ascii
    $s8  = ";function wZp(FXr){var _112crap = \"s\"; return \"\" + FXr + \"\";};var yy = \"qtVXRtZ\",Mc = \"e\";var xgK = yy[\"c\"+\"\\x68\"" ascii
    $s9  = "p = \"s\"; return \"\" + ZPD + \"\";};var LUZ = \"raP1e\",O0 = \"ct\";var NQ = LUZ[\"c\"+\"\\x68\"+\"arAt\"](4),R0 = \"j\";var X" ascii
    $s10 = "_112crap = \"s\"; return \"\" + sBu + \"\";};var H2 = \"sO8aWT\",T2 = H2[\"c\"+\"\\x68\"+\"arAt\"](3);var ina = \"\\x61s\\x64f\"" ascii
    $s11 = "5\\x63t\",C0 = \"t\\x65O\\x62\";var U = \"\\x72e\\x61\",tF = CPf[\"c\"+\"\\x68\"+\"arAt\"](4);function RA(qQ){var _112crap = \"s" ascii
    $s12 = "\"c\"+\"\\x68\"+\"arAt\"](0);var Ajn = \"Cr\";function A0(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};function uF(N){var" ascii
    $s13 = "jI = rYt[\"c\"+\"\\x68\"+\"arAt\"](3),QzV = \"X\";var khN = \"2.\",w0 = \"M\\x53XML\";function tji(j){var _112crap = \"s\"; retu" ascii
    $s14 = "3 = \"TC\\x4d\",eqd = \"get\\x55\";function xlI(O2){var _112crap = \"s\"; return \"\" + O2 + \"\";};function pw(Db){var _112crap" ascii
    $s15 = "function zjf(eDs, Nw){return eDs - Nw;};function yqj(){return v(WW) + D0(SPA) + X0 + R0 + b0(NQ) + uA(O0);};/*@cc_on  @if (@_win" ascii
    $s16 = " : false;};if (x && Y() && yio){function jJ() {return O[Zjs + O4(Mii) + ib + h0(OOC) + j0(Tj) + SDP + LTI(I0) + vwn + yCs + TA(g" ascii
    $s17 = " X + Fnj; yio = true; Fnj = \"07t9gasdf76ags\" + 123313 * X + Fnj; break;}}function Y() {return ((x == yio) && (x == true)) ? tr" ascii
    $s18 = "= \"5k3eeIBF\",B0 = h1[\"c\"+\"\\x68\"+\"arAt\"](3);var MK = \"\\x37\\x67.ex\",Jd = \"hr5T\";var xg = \"1\\x4c\",u1 = \"\\x44\\x" ascii
    $s19 = " TQ = \"lTiQl\",BWl = TQ[\"c\"+\"\\x68\"+\"arAt\"](4);var Y0 = \"el\",s = \"p\\x74.\\x53\\x68\";var yW = \"\\x57\\x53cr\\x69\";f" ascii
    $s20 = "\\x65\\x6ed\";function Ich(u3){var _112crap = \"s\"; return \"\" + u3 + \"\";};function r1(pBW){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}