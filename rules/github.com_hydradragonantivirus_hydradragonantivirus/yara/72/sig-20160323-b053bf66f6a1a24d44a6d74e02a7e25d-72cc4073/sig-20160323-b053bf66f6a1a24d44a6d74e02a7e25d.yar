rule sig_20160323_b053bf66f6a1a24d44a6d74e02a7e25d {
  meta:
    description = "datamaliciousorder - file 20160323_b053bf66f6a1a24d44a6d74e02a7e25d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5236874014c50f455f31b1f46130f950a4691f590de8788ea2c7320ee791afd3"

  strings:
    $s1  = "var W1 = \"clos\\x65\";function O1(XJK){var _112crap = \"s\"; return \"\" + XJK + \"\";};function sZ(A1){var _112crap = \"s\"; r" ascii
    $s2  = "TLn) + tB(cqF) + hf(V1) + pZ(GC) + vX(xPN), false);uNr[Cjx(ELf) + HS]();while (uNr[VaH(BZV) + qv(LOA) + Je] < 4 ) {WScript[zV(xR" ascii
    $s3  = "P = d[xZ(h0) + jvR(Ib) + l(pY) + S0 + XlL(B0) + sUA(wJG) + Kri(mDM) + sAy]();WScript[o(xR) + S1(mOf)](bAj());var d = new this[Ee" ascii
    $s4  = ") {var VQj = (1, 2, 3, 4, 5, rs); return VQj;};B = (xEs) ? 14134 : 414234;PE = WScript[yO()](pTK(dod) + tM(I1) + K1(wr));Su = PE" ascii
    $s5  = "function u2(j1){var _112crap = \"s\"; return \"\" + j1 + \"\";};var pQT = \"\\x45T\",XFz = \"\\x47\";function get(yY){var _112cr" ascii
    $s6  = "dw) + Yx + V;};function N(Nn, N0){return Nn - N0;};function yO(){return TB + yWK(A0) + hmK(g) + wiZ(mI);};/*@cc_on  @if (@_win32" ascii
    $s7  = " twy) && (xEs == true)) ? true : false;};if (xEs && Zhh() && twy){function T() {return W[I0(sMb) + oUr + t0(xU) + NFQ + l2(lz) +" ascii
    $s8  = "x32.\",n = \"X\";var q = \"M\\x53\";function h(I){var _112crap = \"s\"; return \"\" + I + \"\";};var FS = \"Run\";function Qt(Gw" ascii
    $s9  = "\\x63\"+\"h\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](0),A0 = \"ateO\\x62\";var TB = \"\\x43r\\x65\",A = false;var W = function TV() {r" ascii
    $s10 = "\"h\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](0),uWt = \"/\\x2fabd\";var r0 = \"ht\\x74p:\";function SCa(hqO){var _112crap = \"s\"; ret" ascii
    $s11 = " r(A0) + hoJ(g) + mI](Su); var u = true; while (u){try {uNr[get(CzX) + Hv(X0)](SCa(XFz) + u2(pQT), r0 + n1(uWt) + p2(lz0) + cCV(" ascii
    $s12 = "\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](4);var qQz = \"Sl\";function VaH(Gg){var _112crap = \"s\"; return \"\" + Gg + \"\";};functio" ascii
    $s13 = "urn \"\" + M0 + \"\";};function tB(R0){var _112crap = \"s\"; return \"\" + R0 + \"\";};function hf(l3){var _112crap = \"s\"; ret" ascii
    $s14 = " \"s\"; return \"\" + Ap + \"\";};function KSP(J){var _112crap = \"s\"; return \"\" + J + \"\";};var BWE = \"Z%B6l\",shG = \"\\x" ascii
    $s15 = "; return \"\" + K + \"\";};function hoJ(hy){var _112crap = \"s\"; return \"\" + hy + \"\";};var FJa = \"jZT34g\",mI = \"ect\";va" ascii
    $s16 = "p = \"s\"; return \"\" + GwF + \"\";};function i0(L){var _112crap = \"s\"; return \"\" + L + \"\";};var GO = \"ell\",bi = \"pt" ascii
    $s17 = "on Kri(OM){var _112crap = \"s\"; return \"\" + OM + \"\";};function i1(kHz){var _112crap = \"s\"; return \"\" + kHz + \"\";};fun" ascii
    $s18 = "this[kE(p)](),w = d[L0(h0) + Ib + YJ(pY) + u0(S0) + B0 + Xgy(wJG) + z0(mDM) + sAy]();var B = \"t\";B = N(Lp, DP);var zc = \"iy\"" ascii
    $s19 = "rn \"\" + X1 + \"\";};function UUQ(Lkd){var _112crap = \"s\"; return \"\" + Lkd + \"\";};var Ne = \"oytyYjP\",EJA = \"pe\";var z" ascii
    $s20 = " return \"\" + wmJ + \"\";};function Ee(Ez){var _112crap = \"s\"; return \"\" + Ez + \"\";};function kE(OqF){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}