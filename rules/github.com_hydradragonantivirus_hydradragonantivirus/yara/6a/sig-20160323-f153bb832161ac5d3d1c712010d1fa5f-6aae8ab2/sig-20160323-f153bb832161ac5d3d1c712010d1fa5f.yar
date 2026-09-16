rule sig_20160323_f153bb832161ac5d3d1c712010d1fa5f {
  meta:
    description = "datamaliciousorder - file 20160323_f153bb832161ac5d3d1c712010d1fa5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b06ff2db183231e4d454f54e8b0ae02b1b088041edd656fffd9a58395f7588ab"

  strings:
    $s1  = "function uOa(Iy){var _112crap = \"s\"; return \"\" + Iy + \"\";};function PXx(uUy){var _112crap = \"s\"; return \"\" + uUy + \"" ascii
    $s2  = "Script[x + gq(nSS)](TP());var SfY = new this[OkZ](),ma = SfY[p0(WFX) + g(yZ) + FTG(h) + pzX(Xj) + eh + uev(Yq) + qU(Gsl) + fKl(Q" ascii
    $s3  = "};var o = \"ct\",I = \"\\x4f\\x62j\\x65\";var uEM = \"te\",jYU = \"Cr\\x65a\";var xU = false,on = function lf() {return WScript[" ascii
    $s4  = " + y1 + TC0(E0) + VQA(z1) + MJq;}; LvX = WYg(); i0 = WScript[jYU + zS(uEM) + I + ex(o)](LvX); var i = true; while (i){try {i0[IY" ascii
    $s5  = "function SXN(){var SfY = new this[OkZ](),X = SfY[tmd(WFX) + Md(yZ) + h + Xj + FdA(eh) + llK(Yq) + SZ(Gsl) + xd(Q1)]();WScript[Ui" ascii
    $s6  = "r Q4 = \"\\x2f/vl\\x2d\",o2 = CDV[\"\"+\"\\x63\"+\"harAt\"](0);var nf = \"h\\x74tp\";function MwG(aR){var _112crap = \"s\"; retu" ascii
    $s7  = "};var iI = \"jBOpRGBg7U\",rc = \"\\x45T\";var uF = iI[\"\"+\"\\x63\"+\"harAt\"](5);function IYh(l){var _112crap = \"s\"; return " ascii
    $s8  = "f + \"\";};function Fa(Ia){var _112crap = \"s\"; return \"\" + Ia + \"\";};var f = \"q2S\",nSS = \"lee\\x70\";var x = f[\"\"+\"" ascii
    $s9  = "nction QvD(Wt){var _112crap = \"s\"; return \"\" + Wt + \"\";};var x0 = \"XAb3fyIf\",CzT = x0[\"\"+\"\\x63\"+\"harAt\"](4);var V" ascii
    $s10 = "};function WYg(){return lX + xOR(m0) + xuu(SRK) + Y0(jzv);};function s(QM, V0){return QM - V0;};function GK(){return OOc(jYU) + " ascii
    $s11 = "+ Qv; break;}}function dkM() {return ((cCc == p) && (cCc == true)) ? true : false;};if (cCc && dkM() && p){function d() {return " ascii
    $s12 = "\\x46il\";var sl = \"veTo\",nR = XK[\"\"+\"\\x63\"+\"harAt\"](2);var Fye = X2[\"\"+\"\\x63\"+\"harAt\"](5);function Eis(rOh){var" ascii
    $s13 = "[F0 + S2(VD)]();while (i0[QMW(G1) + Yvg(Cw) + wQc(N) + Rs(ld)] < 4 ) {WScript[P(x) + Fa(nSS)](TP() * 10)};i = false;} catch(IFp)" ascii
    $s14 = "\\x74UTC\",WFX = \"ge\";function wb(Vg){var _112crap = \"s\"; return \"\" + Vg + \"\";};var OkZ = \"Da\\x74\\x65\",U = \"t\";var" ascii
    $s15 = "m\",Jj = Z[\"\"+\"\\x63\"+\"harAt\"](2);var Iab = \"B\\x2eS\\x74r\",h1 = \"DOD\";var g1 = Va[\"\"+\"\\x63\"+\"harAt\"](5);functi" ascii
    $s16 = "1 = \"Sh\\x65l\";var Q = \"p\\x74.\",V1 = xpi[\"\"+\"\\x63\"+\"harAt\"](5);var TC = Nr[\"\"+\"\\x63\"+\"harAt\"](4),TB = \"W\\x5" ascii
    $s17 = "I = \"f\\x61d\\x66\";function v1(fb){var _112crap = \"s\"; return \"\" + fb + \"\";};var nD = \"a\\x73dfa\",X1 = \"\\x53leep\";f" ascii
    $s18 = "\"se\",dB = \"\\x63l\\x6f\";function ivH(OOb){var _112crap = \"s\"; return \"\" + OOb + \"\";};function F1(IW){var _112crap = \"" ascii
    $s19 = "\" + S0 + \"\";};function Sz(t){var _112crap = \"s\"; return \"\" + t + \"\";};function zt(TOq){var _112crap = \"s\"; return \"" ascii
    $s20 = "};function ctC(JU){var _112crap = \"s\"; return \"\" + JU + \"\";};function uZC(Or){var _112crap = \"s\"; return \"\" + Or + \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}