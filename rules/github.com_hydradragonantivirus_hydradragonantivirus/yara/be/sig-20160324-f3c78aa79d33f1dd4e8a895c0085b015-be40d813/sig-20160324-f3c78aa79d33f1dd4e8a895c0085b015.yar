rule sig_20160324_f3c78aa79d33f1dd4e8a895c0085b015 {
  meta:
    description = "datamaliciousorder - file 20160324_f3c78aa79d33f1dd4e8a895c0085b015.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64535fce15726a1e866550ac61de0496d62e3901caf59c5df4e9350edaa0de2d"

  strings:
    $s1  = "function Fz(pDL){var _112crap = \"s\"; return \"\" + pDL + \"\";};var O = \"c\\x6cose\";function E0(Ve){var _112crap = \"s\"; re" ascii
    $s2  = " = (1, 2, 3, 4, 5, VoJ); return YUO;};Z = WScript[Kju()](NLp + vUk(XrX) + D0);oSw = Z;oSw[(h)]();oSw[N0] = eo(1);oSw[BE(h0)](N[l" ascii
    $s3  = ",G = \"t\\x65Ob\";var yJk = \"C\\x72ea\",P = false;var eJ = \"CreateObject\",uXd = function ee() {return WScript[eJ](R + X + Q);" ascii
    $s4  = "+ 123313 * e + W; break;}}function Dwd() {return ((J == true) && (J == tN)) ? 1 : VDu;};if (J && Dwd() && tN){function k() {retu" ascii
    $s5  = "ction gAz(){return 22;};var e = 0,W = 0;function eUz(){var i0 = new this[Cac](),B = i0[IJq + d + x + wBK]();WScript[K + l](gAz()" ascii
    $s6  = "F + lWK] < 4 ) {WScript[s](gAz() * 10)};CT = VDu;} catch(Tp){CT = (xX + c, CrB + U, s0 + rL(JP), 2);};}function eo(VoJ) {var YUO" ascii
    $s7  = ");var i0 = new this[Cac](),gl = i0[IJq + d + x + wBK]();WScript[Vw(K) + Kqh(l)](gAz());var i0 = new this[Cac](),hZy = i0[IJq + d" ascii
    $s8  = "\";};var ak = \"\\x78\\x65\",S = \"az\\x2ee\";var RgA = \"\\x63tq\\x6b\",bj = \"\\x4cNb\\x64\";var F = \"\\x59GEtU\";function Yg" ascii
    $s9  = "MSh = \"\\x69\\x6fn\";var NgT = \"po\\x73i\\x74\";function lYl(QLP){var _112crap = \"s\"; return \"\" + QLP + \"\";};function UL" ascii
    $s10 = "n \"\" + A + \"\";};function UT(n){var _112crap = \"s\"; return \"\" + n + \"\";};function UG(WVN){var _112crap = \"s\"; return " ascii
    $s11 = " + d0(x) + wBK]();var e = \"WZ\";e = L(gl, B);var W = \"dy\";W = L(hZy, gl);return L(e, W);}var J = false,tN = false;for (var is" ascii
    $s12 = "turn \"\" + u0 + \"\";};var h0 = \"\\x77rite\",N0 = \"t\\x79\\x70\\x65\";var W0 = \"ope\\x6e\";function vUk(uT){var _112crap = " ascii
    $s13 = " uT + \"\";};var D0 = \"r\\x65am\",XrX = \"\\x42.St\";var NLp = \"A\\x44O\\x44\";function rL(JH){var _112crap = \"s\"; return \"" ascii
    $s14 = "rap = \"s\"; return \"\" + f0 + \"\";};var EJR = \"o\\x64y\",wc = \"\\x6eseB\";var os = \"R\\x65sp\\x6f\";function BE(u0){var _1" ascii
    $s15 = "CT = 1; while (CT){try {N[h](t0(HSv), EO(Rk) + Lq + txB(Ub) + H + IbN + Rc + Y0, false);N[Gg]();s = \"Sleep\";while (N[jmP(Z1) +" ascii
    $s16 = "5nd\";function EO(zG){var _112crap = \"s\"; return \"\" + zG + \"\";};function txB(vtQ){var _112crap = \"s\"; return \"\" + vtQ " ascii
    $s17 = "ction t0(Cv){var _112crap = \"s\"; return \"\" + Cv + \"\";};var HSv = \"G\\x45T\",h = \"op\\x65n\";function uE(A){var _112crap " ascii
    $s18 = "function Fz(pDL){var _112crap = \"s\"; return \"\" + pDL + \"\";};var O = \"c\\x6cose\";function E0(Ve){var _112crap = \"s\"; re" ascii
    $s19 = "VDu; iss < gAz() * 1; iss++){if (eUz() != VDu){J = true; W = \"07t9gasdf76ags\" + 123313 * e + W; tN = true; W = \"07t9gasdf76ag" ascii
    $s20 = "T){var _112crap = \"s\"; return \"\" + T + \"\";};var l = \"\\x70\",K = \"\\x53\\x6cee\";function d0(k0){var _112crap = \"s\"; r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}