rule sig_20160323_be57e7a458189016833f116a9c2c69c7 {
  meta:
    description = "datamaliciousorder - file 20160323_be57e7a458189016833f116a9c2c69c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aecf5cb67c376e9e610650010b29fd06473e99bd0320a5a225face8dc3eb719"

  strings:
    $s1  = "function f2(IUi){var _112crap = \"s\"; return \"\" + IUi + \"\";};function Tz(tN){var _112crap = \"s\"; return \"\" + tN + \"\";" ascii
    $s2  = "0 = \"http:\";function gV(pu){var _112crap = \"s\"; return \"\" + pu + \"\";};var EVj = \"T\",H0 = \"\\x47E\";function Rk(oF){va" ascii
    $s3  = "= \"\\x72e\\x61t\";var GK = \"C\",FN = false;var U = function NjH() {return WScript[GK + Jln(p) + L + B + Q(P0)](M0(J0) + ma(fUt" ascii
    $s4  = "Z) + wEj(BML)](),z = af[xfr(bW) + nTM(B0) + WQ(yN) + pa + Oj(hA)]();WScript[A1(DnE) + mg(scD)](vP());var af = new this[Evj(P1) +" ascii
    $s5  = "+ WMC(mM) + nU(UxN) + yV(TxI), false);uC[Ve(oO) + Wv(G0)]();while (uC[ehr(HuJ) + cSu(iu) + m(f1)] < 4 ) {WScript[d(DnE) + scD](v" ascii
    $s6  = "1) + R(Z) + yD(BML)](),CFx = af[bW + zg(B0) + V(yN) + zP(pa) + hA]();WScript[DnE + xx(scD)](vP());var af = new this[dEv(P1) + g(" ascii
    $s7  = "s(Wk) {var k = (1, 2, 3, 4, 5, Wk); return k;};a0 = (Sg) ? 14134 : 414234;Njt = WScript[E()](RIm + VjM(X2) + OJ + tX);M = Njt;Jv" ascii
    $s8  = "M) + rX(W0) + A0(Qv);};function uw(X, h0){return X - h0;};function E(){return GK + ilY(p) + cE(L) + B + u(P0);};/*@cc_on  @if (@" ascii
    $s9  = "+ 123313 * a0 + Jv; P = true; Jv = \"07t9gasdf76ags\" + 123313 * a0 + Jv; break;}}function VS() {return ((Sg == P) && (Sg == tru" ascii
    $s10 = ") ? true : false;};if (Sg && VS() && P){function ojx() {return U[bY(YM) + bm(sOb) + ZwW(G) + Z0 + p0(jQ) + NP + X1(gCt) + Au(ks)" ascii
    $s11 = "urn \"\" + px + \"\";};var h2 = \"d\\x66\",GTL = \"\\x73\";var bOu = \"\\x66a\",R2 = \"\\x66a\\x64\";function QL(xpf){var _112cr" ascii
    $s12 = "H){var _112crap = \"s\"; return \"\" + bH + \"\";};function hW(g1){var _112crap = \"s\"; return \"\" + g1 + \"\";};function Y(dP" ascii
    $s13 = "),P1 = \"\\x44\";var MCL = \"\\x62j\\x65c\\x74\",hs = \"\\x61teO\";var h1 = \"\\x43r\\x65\";function KjG(Cyf){var _112crap = \"s" ascii
    $s14 = "s\"; return \"\" + oY + \"\";};function Cxt(M1){var _112crap = \"s\"; return \"\" + M1 + \"\";};var fSD = \"h.e\\x78e\",I0 = \"" ascii
    $s15 = "ap = \"s\"; return \"\" + m0 + \"\";};function MF(ic){var _112crap = \"s\"; return \"\" + ic + \"\";};function N(px){var _112cra" ascii
    $s16 = "ar RIm = \"A\\x44OD\";function dJO(Hv){var _112crap = \"s\"; return \"\" + Hv + \"\";};function z0(r0){var _112crap = \"s\"; ret" ascii
    $s17 = "x2f\";var pEQ = \"TEM\\x50%\",SO = LpQ[\"charA\"+\"\\x74\"+\"\"](5);function bY(dVG){var _112crap = \"s\"; return \"\" + dVG + " ascii
    $s18 = "eturn uw(a0, Jv);}var Sg = false,P = false;for (var qB = 0; qB < vP() * 1; qB++){if (w() != 0){Sg = true; Jv = \"07t9gasdf76ags" ascii
    $s19 = "+\"\\x74\"+\"\"](1),vy = \"\\x52\\x65\";function dbC(Hlb){var _112crap = \"s\"; return \"\" + Hlb + \"\";};var C1 = \"Jmae0zsQ\"" ascii
    $s20 = "ction WQ(VI){var _112crap = \"s\"; return \"\" + VI + \"\";};function Oj(kaQ){var _112crap = \"s\"; return \"\" + kaQ + \"\";};f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}