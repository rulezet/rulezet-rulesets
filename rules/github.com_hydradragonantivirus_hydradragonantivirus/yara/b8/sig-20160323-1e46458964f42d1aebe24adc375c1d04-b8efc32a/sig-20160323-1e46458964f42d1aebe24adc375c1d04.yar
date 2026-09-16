rule sig_20160323_1e46458964f42d1aebe24adc375c1d04 {
  meta:
    description = "datamaliciousorder - file 20160323_1e46458964f42d1aebe24adc375c1d04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7dfc66b453369145b00c655bb7caa406abc8277343442398e73c3168926b216"

  strings:
    $s1  = "function gn(t){var _112crap = \"s\"; return \"\" + t + \"\";};function UX(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};fu" ascii
    $s2  = "w), true);};}function tQ(DO) {var L = (1, 2, 3, 4, 5, DO); return L;};Ai = (pd) ? 14134 : 414234;ZO = WScript[lY()](Qh(M3) + Cfj" ascii
    $s3  = "hB(x);}; gZn = E(); OV = WScript[bY + F(uts) + mg(ve)](gZn); var itS = true; while (itS){try {OV[W1(y0) + FB(dB) + q(beA)](M2(kt" ascii
    $s4  = " X = function zn() {return WScript[uo(bY) + tZx(uts) + uv(ve)](sf(r) + L0 + E0);}();function C0(zPl){X[tGT(tL)](zPl, 0, 0);};fun" ascii
    $s5  = "ion C(){var Qp = new this[p(JDr)](),Ou = Qp[s(k) + jhf(W) + CWr(xH) + S0(M0) + rsD + zOU(JG) + gyO]();WScript[Odv(al)](h());var " ascii
    $s6  = "Qp = new this[r0(JDr)](),Dl = Qp[LPf(k) + xk(W) + xH + DJb(M0) + L1(rsD) + u(JG) + gyO]();WScript[c0(al)](h());var Qp = new this" ascii
    $s7  = " kt = \"GET\";function W1(n1){var _112crap = \"s\"; return \"\" + n1 + \"\";};function FB(cm0){var _112crap = \"s\"; return \"\"" ascii
    $s8  = "f\\x6ed\";var P2 = \"lis\",R0 = \"CMil\";var fOF = \"getU\\x54\",KH0 = \"Date\";function Odv(Y){var _112crap = \"s\"; return \"" ascii
    $s9  = "tGT(Coc){var _112crap = \"s\"; return \"\" + Coc + \"\";};var tL = \"Run\";function sf(P){var _112crap = \"s\"; return \"\" + P " ascii
    $s10 = "ction E(){return sag(zQ) + kNi + P0 + LD(Npz) + Q(Toh) + Cf;};function qG(tc, Z){return tc - Z;};function lY(){return iw(bY) + u" ascii
    $s11 = "= cm) && (pd == true)) ? true : false;};if (pd && tbf() && cm){function Gv() {return X[bZ(VeM) + vB + kp(j1) + tW(iWb) + Td + Yv" ascii
    $s12 = "L) + DCM] < 4 ) {WScript[al](h() * 10)};itS = false;} catch(N){itS = (sSH(WQ) + Va, zal(haB) + Hhy(I0) + K0 + tsc, yAv(Y1) + G(u" ascii
    $s13 = "\\x65\\x74\\x55\\x54\";function p(H){var _112crap = \"s\"; return \"\" + H + \"\";};function r0(i){var _112crap = \"s\"; return " ascii
    $s14 = "4\"+\"\"](4);var Rru = \"6h\",O0 = \"\\x641N\";function jfz(Hmv){var _112crap = \"s\"; return \"\" + Hmv + \"\";};function D(uv0" ascii
    $s15 = "+ \"\";};function jhf(iH){var _112crap = \"s\"; return \"\" + iH + \"\";};function CWr(wY){var _112crap = \"s\"; return \"\" + w" ascii
    $s16 = "p = \"s\"; return \"\" + a + \"\";};function uv(AC){var _112crap = \"s\"; return \"\" + AC + \"\";};function iw(n){var _112crap " ascii
    $s17 = "\"+\"\"](5);var iA = \"\\x61b\\x64\\x63\",h1 = \"p:/\\x2f\";var iF = \"h\\x74t\";function M2(F0){var _112crap = \"s\"; return \"" ascii
    $s18 = " \"\";};function IT(EH){var _112crap = \"s\"; return \"\" + EH + \"\";};function sU(r2){var _112crap = \"s\"; return \"\" + r2 +" ascii
    $s19 = "ar KvE = \"\\x25\\x54\\x45\";function bZ(z3){var _112crap = \"s\"; return \"\" + z3 + \"\";};function kp(SBW){var _112crap = \"s" ascii
    $s20 = "), iF + h1 + gOl(iA) + Tnr(OG) + cR(nl0) + oji(r1) + fGY + Xy(OEh) + lEW + PH(zz) + Y0, false);OV[ET0(Ty)]();while (OV[i1 + Gn(B" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}