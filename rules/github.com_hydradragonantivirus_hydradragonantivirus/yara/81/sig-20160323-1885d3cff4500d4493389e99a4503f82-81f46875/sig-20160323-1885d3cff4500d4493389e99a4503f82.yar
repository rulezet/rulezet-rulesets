rule sig_20160323_1885d3cff4500d4493389e99a4503f82 {
  meta:
    description = "datamaliciousorder - file 20160323_1885d3cff4500d4493389e99a4503f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f70198ba3e450552ccef849b913d04b92cd8fd21c74652ba854d84ff77fe8ae"

  strings:
    $s1  = "function Y(Cze){var _112crap = \"s\"; return \"\" + Cze + \"\";};var jis = \"\\x73\\x65\",f3 = \"\\x63lo\";function c0(W3){var _" ascii
    $s2  = "rap = \"s\"; return \"\" + qG + \"\";};var B0 = \"%/\",zNn = \"\\x25TEMP\";function QPU(eA){var _112crap = \"s\"; return \"\" + " ascii
    $s3  = " F(Tn) + n0(j1) + c(TdU)]();WScript[k(Uyi) + o0](vha());var wuG = new this[Qgr(D) + pf + q1(W1)](),fx = wuG[mv(Dq) + ugW(olg) + " ascii
    $s4  = "kK(WQ) + CpA(YP) + cG(YHa);}; ECZ = a(); q = WScript[Wu(GuE) + NOW(f) + r(Jaf) + N(WjJ) + P0(mY)](ECZ); var UoJ = true; while (U" ascii
    $s5  = "Script[SpS()](GgP(Gp) + wT(R0) + jZ(F1) + hg(zMK));ECZ = pP;B = (I) ? m : B;ECZ[(K + Ff(Wi))]();B = (I) ? m : B;ECZ[yV(HM) + x2(" ascii
    $s6  = "Tn + NY(j1) + MPH(TdU)]();WScript[a0(Uyi) + ho(o0)](vha());var wuG = new this[sI(D) + pf + UpU(W1)](),PVv = wuG[Dq + SrC(olg) + " ascii
    $s7  = "\\x683\";var L1 = \"\\x66r\",pf0 = \"\\x65\\x77.\";var QB = \"\\x70\\x73c\\x72\",MZ = \"\\x2f\\x2f\\x74o\";var X0 = \"http:\";fu" ascii
    $s8  = "){W[uTy(h0)](y, 0, 0);};function a(){return ndF(XdX) + BXO(j) + niP(O0) + e(FR);};function pDw(q0, x){return q0 - x;};function S" ascii
    $s9  = "df76ags\" + 123313 * m + B; break;}}function Cx() {return ((Df == I) && (Df == true)) ? true : false;};if (Df && Cx() && I){func" ascii
    $s10 = "= false,W = function wj() {return WScript[Zh(GuE) + pES(f) + Hcl(Jaf) + Cao(WjJ) + mY](HKg + KF(Q) + VmE + GE);}();function AY(y" ascii
    $s11 = "X(Q0) + S + Hn(aO)] < 4 ) {WScript[t(Uyi) + o0](vha() * 10)};UoJ = false;} catch(o){UoJ = (hcA + I1(Qi), MO(DH) + oDO(r2) + f1(L" ascii
    $s12 = "\\x66a\",Z2 = fA[\"char\"+\"\\x41\"+\"t\"](4);var W2 = \"\\x61fd\";function MO(C){var _112crap = \"s\"; return \"\" + C + \"\";}" ascii
    $s13 = " + jS + \"\";};function jZ(cQ){var _112crap = \"s\"; return \"\" + cQ + \"\";};function hg(Tl){var _112crap = \"s\"; return \"\"" ascii
    $s14 = "I(PN){var _112crap = \"s\"; return \"\" + PN + \"\";};function UpU(BE){var _112crap = \"s\"; return \"\" + BE + \"\";};var Tz = " ascii
    $s15 = " _112crap = \"s\"; return \"\" + ICk + \"\";};function c(Fdg){var _112crap = \"s\"; return \"\" + Fdg + \"\";};function mv(m0){v" ascii
    $s16 = "2crap = \"s\"; return \"\" + u2 + \"\";};function sJR(j2){var _112crap = \"s\"; return \"\" + j2 + \"\";};var u1 = \"8cj\\x73\"," ascii
    $s17 = "on BXO(Vgl){var _112crap = \"s\"; return \"\" + Vgl + \"\";};function niP(uK){var _112crap = \"s\"; return \"\" + uK + \"\";};fu" ascii
    $s18 = "{var _112crap = \"s\"; return \"\" + Z + \"\";};function ocW(OF){var _112crap = \"s\"; return \"\" + OF + \"\";};function Wu(A){" ascii
    $s19 = "ap = \"s\"; return \"\" + SlM + \"\";};var YHa = \"\\x2e\\x65xe\",YP = \"V\\x33K\";var WQ = \"W0cH\",RwM = \"O6\\x49f\";function" ascii
    $s20 = " = \"s\"; return \"\" + A + \"\";};function NOW(Gvj){var _112crap = \"s\"; return \"\" + Gvj + \"\";};function r(W0){var _112cra" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}