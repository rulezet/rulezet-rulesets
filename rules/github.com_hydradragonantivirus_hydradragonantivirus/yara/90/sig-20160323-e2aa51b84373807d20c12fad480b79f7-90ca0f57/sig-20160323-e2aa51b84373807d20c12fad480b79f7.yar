rule sig_20160323_e2aa51b84373807d20c12fad480b79f7 {
  meta:
    description = "datamaliciousorder - file 20160323_e2aa51b84373807d20c12fad480b79f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8eefee132839e5745b50331e20141e3ecdd4949c52d6da006e69d4e2a7a2c306"

  strings:
    $s1  = "function nt(Ol){var _112crap = \"s\"; return \"\" + Ol + \"\";};function ey(l5){var _112crap = \"s\"; return \"\" + l5 + \"\";};" ascii
    $s2  = "mi) + mh](),YO = EX[tnB(gM) + gL(CW) + c + q(fL) + O(SEi) + X(YP)]();WScript[Z0(YgT) + G0(z0)](zS());var EX = new this[umi + Ze(" ascii
    $s3  = "PX(qxf) + l2 + N1(f0) + Ms(T1) + J0(GCf), false);wC[TZJ(Y) + gpP(DVJ)]();while (wC[de(Y0) + Rz + ywR(Sm) + n3] < 4 ) {WScript[l0" ascii
    $s4  = "x61t\",R = \"C\";var EJQ = false,reI = function dF() {return WScript[qHL(R) + qM(pU) + Z(Gp) + Gov(u) + L(fzE)](gm(aij) + hG + e" ascii
    $s5  = "s[M(umi) + dyw(mh)](),DR = EX[k(gM) + CW + sqZ(c) + z(fL) + SEi + wJK(YP)]();WScript[YgT + RSk(z0)](zS());var EX = new this[yO(u" ascii
    $s6  = "pO) {var Oo = (1, 2, 3, 4, 5, YpO); return Oo;};NOO = (chk) ? 14134 : 414234;S1 = WScript[hg()](aQ(xt) + gUa(P0) + G1(pa) + SFw(" ascii
    $s7  = ") + Cyk;};function S(MiA, TF){return MiA - TF;};function hg(){return x0(R) + UP(pU) + jo(Gp) + rR(u) + AO(fzE);};/*@cc_on  @if (" ascii
    $s8  = "3313 * NOO + LL; S0 = true; LL = \"07t9gasdf76ags\" + 123313 * NOO + LL; break;}}function ODJ() {return ((chk == S0) && (chk == " ascii
    $s9  = "crap = \"s\"; return \"\" + Dc + \"\";};var DUW = \"NA2Y5\",TK = \"EZ.ruJ\";var L2 = \"ea\\x6d\",Kvc = \"tr\";var XC = \"\\x53\"" ascii
    $s10 = "ue)) ? true : false;};if (chk && ODJ() && S0){function pf() {return reI[s0(QA) + FNz(cT) + k1(jI) + Pn(ld) + t + l1(N) + ubN(owR" ascii
    $s11 = " \"\";};var qC = \"afa\",N2 = \"\\x61fd\";function NKP(vW){var _112crap = \"s\"; return \"\" + vW + \"\";};function Co(l3){var _" ascii
    $s12 = "\\x74\"+\"\"](2);var pa = \"\\x42\",P0 = \"DO\\x44\";var xt = DUW[\"charA\"+\"\\x74\"+\"\"](1);function sQ(d){var _112crap = \"s" ascii
    $s13 = "tion LWb(hTc){var _112crap = \"s\"; return \"\" + hTc + \"\";};function r(chW){var _112crap = \"s\"; return \"\" + chW + \"\";};" ascii
    $s14 = "fL = \"\\x69se\";var c = \"\\x69ll\",CW = \"TCM\";var gM = \"\\x67etU\";function M(wl){var _112crap = \"s\"; return \"\" + wl + " ascii
    $s15 = "r _112crap = \"s\"; return \"\" + y0 + \"\";};function n(HcR){var _112crap = \"s\"; return \"\" + HcR + \"\";};function Ug(sCQ){" ascii
    $s16 = "+ \"\";};function G2(qQ){var _112crap = \"s\"; return \"\" + qQ + \"\";};var l4 = \"ueS\",F2 = l4[\"charA\"+\"\\x74\"+\"\"](1);v" ascii
    $s17 = "yx = \"ToFi\";var evv0 = \"Sa\\x76\\x65\";function y1(x5){var _112crap = \"s\"; return \"\" + x5 + \"\";};function jl(J1){var _1" ascii
    $s18 = " \"/baro\";var Dp = \":/\",T0 = \"\\x68\\x74t\\x70\";function pB(Nyg){var _112crap = \"s\"; return \"\" + Nyg + \"\";};var h1 = " ascii
    $s19 = " = \"s\"; return \"\" + sCQ + \"\";};var Tm = \"mS8edDB\",fzE = \"\\x6a\\x65ct\";var u = \"O\\x62\",Gp = Tm[\"charA\"+\"\\x74\"+" ascii
    $s20 = "%T\";function s0(nE){var _112crap = \"s\"; return \"\" + nE + \"\";};function FNz(n1){var _112crap = \"s\"; return \"\" + n1 + " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}