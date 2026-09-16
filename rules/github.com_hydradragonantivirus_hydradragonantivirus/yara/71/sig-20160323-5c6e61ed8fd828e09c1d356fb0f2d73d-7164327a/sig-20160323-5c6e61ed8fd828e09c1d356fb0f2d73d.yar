rule sig_20160323_5c6e61ed8fd828e09c1d356fb0f2d73d {
  meta:
    description = "datamaliciousorder - file 20160323_5c6e61ed8fd828e09c1d356fb0f2d73d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "934cc4da5ef220d88d0c99e50c535365fe47947839ccfe94cdf4a52e17876d37"

  strings:
    $s1  = " d0(W) + m(P) + vba + W1(eyA) + EfK + pIO(OO) + dA(W0)]();WScript[Do + rYy(l0) + db(Ynq)](UlK());var Yj = new this[cfK(lKi)](),E" ascii
    $s2  = "(KUR);}; xg = xpi(); sr = WScript[ru(Z1) + Uxp(El) + Kfp(j) + N(Z2) + j0(yI)](xg); var D = true; while (D){try {sr[b0(AYZ) + bT]" ascii
    $s3  = " = false,Z0 = function M() {return WScript[tzG(Z1) + KB(El) + ym(j) + Uf(Z2) + h(yI)](YjS(tFX) + z + d(KrH) + OW + HAQ);}();func" ascii
    $s4  = "+ P0(vba) + R(eyA) + EfK + OO + R0(W0)]();WScript[WwP(Do) + PFL(l0) + yU(Ynq)](UlK());var Yj = new this[y0(lKi)](),qUY = Yj[lE +" ascii
    $s5  = "df76ags\" + 123313 * yo + y; I0 = true; y = \"07t9gasdf76ags\" + 123313 * yo + y; break;}}function AUP() {return ((ig == I0) && " ascii
    $s6  = "turn \"\" + Qi + \"\";};var oCp = \"Run\";function YjS(jL){var _112crap = \"s\"; return \"\" + jL + \"\";};function d(HjL){var _" ascii
    $s7  = " == true)) ? true : false;};if (ig && AUP() && I0){function Pn() {return Z0[NWO + wZH(xAU) + hPx(q0) + Ay(FA) + N0(No) + grt(Ng)" ascii
    $s8  = "q) + k2 + LNI(IA) + axS(G0)] < 4 ) {WScript[c2(Do) + l0 + z0(Ynq)](UlK() * 10)};D = false;} catch(SVK){D = (SKh(roY) + R2(GE), w" ascii
    $s9  = "function VQP(GQ){var _112crap = \"s\"; return \"\" + GQ + \"\";};function Ij(rKS){var _112crap = \"s\"; return \"\" + rKS + \"\"" ascii
    $s10 = "\\x64\\x61\\x66\";function wDZ(dM){var _112crap = \"s\"; return \"\" + dM + \"\";};function iMt(FV){var _112crap = \"s\"; return" ascii
    $s11 = "; return \"\" + JMm + \"\";};function l2(nG){var _112crap = \"s\"; return \"\" + nG + \"\";};var KUR = \"x\\x65\",CUH = \"e\";va" ascii
    $s12 = "function VQP(GQ){var _112crap = \"s\"; return \"\" + GQ + \"\";};function Ij(rKS){var _112crap = \"s\"; return \"\" + rKS + \"\"" ascii
    $s13 = "){var _112crap = \"s\"; return \"\" + gw + \"\";};function O(Rh){var _112crap = \"s\"; return \"\" + Rh + \"\";};function k1(vQs" ascii
    $s14 = "x2e\",AD = \"H\\x41qIi\";var a1 = \"l\\x58\",ojH = \"\\x30nJt9\";var PZr = \"s\";function kbL(Fq){var _112crap = \"s\"; return " ascii
    $s15 = " _112crap = \"s\"; return \"\" + XSn + \"\";};function l(dXv){var _112crap = \"s\"; return \"\" + dXv + \"\";};var Fv = \"st\",Q" ascii
    $s16 = " b0(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};function C0(QUI){var _112crap = \"s\"; return \"\" + QUI + \"\";};var i0" ascii
    $s17 = "urn \"\" + QWz + \"\";};function pIO(n){var _112crap = \"s\"; return \"\" + n + \"\";};function dA(C){var _112crap = \"s\"; retu" ascii
    $s18 = " lY(o2){var _112crap = \"s\"; return \"\" + o2 + \"\";};var pbU = \"\\x64y\",lW = \"\\x65Bo\";var EaV = \"ns\",PB = \"s\\x70o\";" ascii
    $s19 = " \"\\x41\";function k4(f){var _112crap = \"s\"; return \"\" + f + \"\";};var fs = \"a\",m0 = fs[\"ch\"+\"\\x61\"+\"rA\"+\"\\x74" ascii
    $s20 = "ar _112crap = \"s\"; return \"\" + gO + \"\";};function Z3(kUu){var _112crap = \"s\"; return \"\" + kUu + \"\";};var e1 = \"ion" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}