rule sig_20160324_a93d6416feb38d6ba4985445c6966b7d {
  meta:
    description = "datamaliciousorder - file 20160324_a93d6416feb38d6ba4985445c6966b7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7c37ea95942f166952b23067b46695fc88dfd5c6db15b8985fb93d315501c1d"

  strings:
    $s1  = "ZX + yva + c + aGR + sm + xHW](CQj + fE) + YPE + YIc + K + KpD;}; q = z(); JJO = WScript[nH](q); var S0 = 1; while (S0){try {JJO" ascii
    $s2  = "));var N0 = new this[ZWA(TA)](),Q = N0[hxA + k + j(Ob) + oQ(t0)]();WScript[TPK + o0](N());var N0 = new this[TA](),dd = N0[hxA + " ascii
    $s3  = "4, 5, Qbs); return I;};D = WScript[S()](i + r0 + i0(rZ));q = D;q[(xy(t1))]();q[jh] = zqc(1);q[pra(DgE)](JJO[q0 + BOn(FK) + Nb]);" ascii
    $s4  = " = \"te\\x4fbj\",YZE = \"C\\x72ea\";var hT = false,nH = \"CreateObject\";var t = function Z() {return WScript[nH](Bu(LF) + tMZ +" ascii
    $s5  = "ion N(){return 22;};var Zy = 0,rx = 0;function P(){var N0 = new this[TA](),o = N0[hxA + YVw(k) + Ob + t0]();WScript[TPK + o0](N(" ascii
    $s6  = "function ycB(G1){var _112crap = \"s\"; return \"\" + G1 + \"\";};var KY = \"\\x65\",ku = \"cl\\x6fs\";var v2 = \"\\x65\",z0 = \"" ascii
    $s7  = "3313 * Zy + rx; break;}}function Y() {return ((p == true) && (p == KcP)) ? 1 : G;};if (p && Y() && KcP){function f() {return t[r" ascii
    $s8  = "on BOn(hjG){var _112crap = \"s\"; return \"\" + hjG + \"\";};var Nb = \"\\x6fd\\x79\",FK = \"on\\x73eB\";var q0 = \"R\\x65sp\";f" ascii
    $s9  = "k + Ob + t0]();var Zy = \"s\";Zy = y0(Q, o);var rx = \"b\";rx = y0(dd, Q);return y0(Zy, rx);}var p = false,KcP = false;for (var " ascii
    $s10 = "[t1](FoC, e + w + Oea + k0 + Sv + A + ByO + K0(kKv), false);JJO[XL(X)]();hjq = \"Sleep\";while (JJO[FP + G0(oQ0) + NUx] < 4 ) {W" ascii
    $s11 = " + zq + \"\";};var X = \"se\\x6ed\";function K0(E0){var _112crap = \"s\"; return \"\" + E0 + \"\";};var kKv = \"\\x73a\",ByO = " ascii
    $s12 = " \"\" + IWZ + \"\";};function j(Gz){var _112crap = \"s\"; return \"\" + Gz + \"\";};function oQ(dUP){var _112crap = \"s\"; retur" ascii
    $s13 = " G; iT < N() * 1; iT++){if (P() != G){p = true; rx = \"07t9gasdf76ags\" + 123313 * Zy + rx; KcP = true; rx = \"07t9gasdf76ags\" " ascii
    $s14 = "(WI){var _112crap = \"s\"; return \"\" + WI + \"\";};var ms = \"\\x65\\x6cl\",tMZ = \"pt.\\x53\\x68\";var LF = \"\\x57Scri\",QS " ascii
    $s15 = "function ycB(G1){var _112crap = \"s\"; return \"\" + G1 + \"\";};var KY = \"\\x65\",ku = \"cl\\x6fs\";var v2 = \"\\x65\",z0 = \"" ascii
    $s16 = " return \"\" + n + \"\";};function Lnw(Pxq){var _112crap = \"s\"; return \"\" + Pxq + \"\";};var dNb = \"f\\x61\",EG = \"afd\\x6" ascii
    $s17 = "s\\x64f\",him = \"f\\x61df\";var OXt = \"\\x61\",r = \"\\x61s\\x64\\x66\";function G0(a0){var _112crap = \"s\"; return \"\" + a0" ascii
    $s18 = "12crap = \"s\"; return \"\" + wl + \"\";};var rZ = \"\\x61m\",r0 = \".St\\x72e\";var i = \"A\\x44\\x4fD\\x42\";function Y0(n){va" ascii
    $s19 = "\";function xy(xbN){var _112crap = \"s\"; return \"\" + xbN + \"\";};var t1 = \"o\\x70e\\x6e\",KpD = \"\\x65\";var K = \"y\\x2ee" ascii
    $s20 = " + xx + \"\";};var TA = \"\\x44at\\x65\",v0 = \"\\x52u\\x6e\";var gUb = \"T\\x50\",v = \"ML\\x48T\";var x = \"L\\x32.X\",P0 = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}