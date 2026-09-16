rule sig_20160324_6531f9762e8fd25d342091c47b4da692 {
  meta:
    description = "datamaliciousorder - file 20160324_6531f9762e8fd25d342091c47b4da692.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8063ab61cd861e9f8da0bdf08d67132ad5d257dace2d4fee1e8b073f2569e50e"

  strings:
    $s1  = "b(nb) + Nd + Avi(N0)]();WScript[G1(qd) + iGx(V)](p());var adO = new this[Xe(J) + otv](),E0 = adO[nE(gJx0) + W0 + Ip(hJ) + ts(nb)" ascii
    $s2  = "pz(oBt) + Mp(xnk) + qfk(I) + rK(x0) + aAe;}; UaR = ZH(); vsQ = WScript[RM + dko(O0) + wsX + g(Ifa) + Y(AYX)](UaR); var gC = true" ascii
    $s3  = "j = function A() {return WScript[TS(RM) + IF(O0) + E1(wsX) + E2(Ifa) + yg(AYX)](CJo(G0) + j0(p0) + c0(ov) + icG(vVV));}();functi" ascii
    $s4  = " + Nd + ZWD(N0)]();WScript[mq(qd) + Ev(V)](p());var adO = new this[Psq(J) + a0(otv)](),tSQ = adO[M0(gJx0) + CH(W0) + cJ(hJ) + e0" ascii
    $s5  = "on US(ai){j[nLl + U](ai, 0, 0);};function ZH(){return eIA(jo) + s(gF) + siC(LE) + asb(x) + e;};function NJ(WF, DNb){return WF - " ascii
    $s6  = "sdf76ags\" + 123313 * o + YKl; break;}}function XVM() {return ((O == h) && (O == true)) ? true : false;};if (O && XVM() && h){fu" ascii
    $s7  = " + y0(CL), false);vsQ[fks(OU) + ME(H1)]();while (vsQ[Lq(QnF) + JIK + hrY] < 4 ) {WScript[qd + V](p() * 10)};gC = false;} catch(y" ascii
    $s8  = "function h0(EU){var _112crap = \"s\"; return \"\" + EU + \"\";};var fJ = \"\\x73e\",PX = \"clo\";function iBf(eGo){var _112crap " ascii
    $s9  = "w){gC = (rE + P1(k), vXr(z3) + iG + vPi(UOH), ZP(aR) + XT(c3), true);};}function r(X) {var E = (1, 2, 3, 4, 5, X); return E;};o " ascii
    $s10 = "tion jvL(K0){var _112crap = \"s\"; return \"\" + K0 + \"\";};function oL(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};fun" ascii
    $s11 = "function h0(EU){var _112crap = \"s\"; return \"\" + EU + \"\";};var fJ = \"\\x73e\",PX = \"clo\";function iBf(eGo){var _112crap " ascii
    $s12 = "\"s\"; return \"\" + jEm + \"\";};var Rw = \"\\x6f\\x6e\",J3 = \"i\";var r1 = \"o\\x73i\\x74\",RP = \"p\";function l(Yxo){var _1" ascii
    $s13 = "63\",WYE = \"i\\x65se\";var v1 = \":/\\x2fd\",hN = \"p\";var w1 = \"htt\";function QsW(c1){var _112crap = \"s\"; return \"\" + c" ascii
    $s14 = "\",F0 = CU[\"charA\"+\"\\x74\"+\"\"](1);var CMn = \"typ\",S = \"e\\x6e\";var t0 = \"op\";function Yt(g1){var _112crap = \"s\"; r" ascii
    $s15 = "var _112crap = \"s\"; return \"\" + wz + \"\";};function Gb(jWF){var _112crap = \"s\"; return \"\" + jWF + \"\";};function Avi(a" ascii
    $s16 = "ap = \"s\"; return \"\" + Y2 + \"\";};function Sx(wI){var _112crap = \"s\"; return \"\" + wI + \"\";};var FIP = \"e\",fz = \"\\x" ascii
    $s17 = "crap = \"s\"; return \"\" + aps + \"\";};function nE(M){var _112crap = \"s\"; return \"\" + M + \"\";};function Ip(rn){var _112c" ascii
    $s18 = "_112crap = \"s\"; return \"\" + M1 + \"\";};function XI(Pj){var _112crap = \"s\"; return \"\" + Pj + \"\";};function e5(jEm){var" ascii
    $s19 = " _112crap = \"s\"; return \"\" + SaQ + \"\";};function hbp(s0){var _112crap = \"s\"; return \"\" + s0 + \"\";};function v(z0){va" ascii
    $s20 = "UOH = \"\\x64\\x66\",iG = \"\\x64\\x66as\";var z3 = \"fa\";function P1(VxZ){var _112crap = \"s\"; return \"\" + VxZ + \"\";};var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}