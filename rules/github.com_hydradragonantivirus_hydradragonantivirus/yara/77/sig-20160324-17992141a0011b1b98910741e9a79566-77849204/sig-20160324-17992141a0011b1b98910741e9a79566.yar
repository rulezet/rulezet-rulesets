rule sig_20160324_17992141a0011b1b98910741e9a79566 {
  meta:
    description = "datamaliciousorder - file 20160324_17992141a0011b1b98910741e9a79566.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9868d1dad44d6cc886caf7d3c16c5e60820ed26c6722346e0c55da3c5680d1"

  strings:
    $s1  = "function U(VI){var _112crap = \"s\"; return \"\" + VI + \"\";};function t(mKn){var _112crap = \"s\"; return \"\" + mKn + \"\";};" ascii
    $s2  = " {return WScript[Er(zv) + g0(g) + wb(o) + fl + H + jiI(Xt)](FF(Zox) + Lg(spb) + F + mL);}();function SL(uUY){dx[r(N)](uUY, 0, 0)" ascii
    $s3  = "[s(UA) + AN + WiY(S0)](K());var dfc = new this[Zf(zQ) + lLt(RwA)](),mz = dfc[wnE + VTt + M + xW(dPl) + GTM(B0)]();WScript[UA + T" ascii
    $s4  = "(RbJ);}; m = CHf(); OlP = WScript[zv + g + MmB(o) + fl + DSr(H) + Xt](m); var XxW = true; while (XxW){try {OlP[l1(Nu)](S1(W0), h" ascii
    $s5  = ";var Qrh = 0,yeY = 0;function Q(){var dfc = new this[hcH(zQ) + RwA](),bf = dfc[Qab(wnE) + i0(VTt) + M + Iuy(dPl) + B0]();WScript" ascii
    $s6  = " = \"getUT\";function hcH(n){var _112crap = \"s\"; return \"\" + n + \"\";};function Zf(D0){var _112crap = \"s\"; return \"\" + " ascii
    $s7  = ";};function CHf(){return qYG + hbC(u) + W(wX) + alM(cpY) + eG;};function GB(y, mDR){return y - mDR;};function Jbt(){return G0(zv" ascii
    $s8  = "+ yeY; break;}}function Z() {return ((xM == GN) && (xM == true)) ? true : false;};if (xM && Z() && GN){function w() {return dx[E" ascii
    $s9  = "unction WiY(IAG){var _112crap = \"s\"; return \"\" + IAG + \"\";};function TMp(NCj){var _112crap = \"s\"; return \"\" + NCj + \"" ascii
    $s10 = "H\";var wX = \"\\x4d\",u = \"2.\\x58\";var qYG = \"\\x4dSXML\";function r(jcb){var _112crap = \"s\"; return \"\" + jcb + \"\";};" ascii
    $s11 = " w2(FMp) + R0(A0) + Di(NL)] < 4 ) {WScript[UA + AN + GVz(S0)](K() * 10)};XxW = false;} catch(l){XxW = (CMb(yqZ) + Sp + TeH(c1), " ascii
    $s12 = "\",IJu = \"\\x6co\";var gMN = \"c\";function q2(JI){var _112crap = \"s\"; return \"\" + JI + \"\";};function K4(IsI){var _112cra" ascii
    $s13 = "\"\" + a0 + \"\";};function V(yDl){var _112crap = \"s\"; return \"\" + yDl + \"\";};function OO(EMJ){var _112crap = \"s\"; retur" ascii
    $s14 = "\"; return \"\" + Dq + \"\";};function G0(Uh){var _112crap = \"s\"; return \"\" + Uh + \"\";};function S(rh){var _112crap = \"s" ascii
    $s15 = "x + \"\";};function nsE(Hyl){var _112crap = \"s\"; return \"\" + Hyl + \"\";};function j(poX){var _112crap = \"s\"; return \"\" " ascii
    $s16 = "+ rh + \"\";};function Zi(PJS){var _112crap = \"s\"; return \"\" + PJS + \"\";};function w0(c){var _112crap = \"s\"; return \"\"" ascii
    $s17 = "r(Lk){var _112crap = \"s\"; return \"\" + Lk + \"\";};var fdY = \"tt5Dh\",wZK = \"av8TOe9E2\";var Xt = \"\\x62\\x6ae\\x63t\",H =" ascii
    $s18 = "crap = \"s\"; return \"\" + fjC + \"\";};function oLc(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};function Fb(Aox){var _" ascii
    $s19 = ";var W0 = \"G\\x45T\";function l1(F1){var _112crap = \"s\"; return \"\" + F1 + \"\";};function BY(E2){var _112crap = \"s\"; retu" ascii
    $s20 = " g2(udb){var _112crap = \"s\"; return \"\" + udb + \"\";};function M2(Kk){var _112crap = \"s\"; return \"\" + Kk + \"\";};functi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}