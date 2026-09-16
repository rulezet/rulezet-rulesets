rule sig_20160323_acea35640d78db72a7ac58899a2e296b {
  meta:
    description = "datamaliciousorder - file 20160323_acea35640d78db72a7ac58899a2e296b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c93ad7a8d1002131fe3294212af63d4b133c3ab5e0d36928ebd09c215ac942e0"

  strings:
    $s1  = "function bB(Gn0){var _112crap = \"s\"; return \"\" + Gn0 + \"\";};function z1(Rf){var _112crap = \"s\"; return \"\" + Rf + \"\";" ascii
    $s2  = "* d + hci; G = true; hci = \"07t9gasdf76ags\" + 123313 * d + hci; break;}}function lh() {return ((Xsy == G) && (Xsy == true)) ? " ascii
    $s3  = "c) + Xi(PlK) + OUR(p) + TXR(sd) + Si + ZPB]();WScript[WhH(AJ) + xu(D0)](GZ());var In = new this[GRb(b0)](),jz = In[yll + O(Er) +" ascii
    $s4  = "p) + MP(sd) + q0(Si) + T0(ZPB)]();WScript[GIC(AJ) + V1(D0)](GZ());var In = new this[k0(b0)](),Wc = In[Vtg(yll) + c0(Er) + SHO(Zw" ascii
    $s5  = " 3, 4, 5, tw); return J;};d = (Xsy) ? 14134 : 414234;VgO = WScript[y()](g + In0(q2) + UA + y2(fVw));vn = VgO;hci = (G) ? d : hci" ascii
    $s6  = "l = false,R = function aZ() {return WScript[Z + mtM + MF + CG](pqq(psM) + b(B0) + B1(C) + QKJ(FSS));}();function aAC(xCV){R[D(gI" ascii
    $s7  = "rR) + wjx(qg), false);B[OCj(S0) + WIB(rcp)]();while (B[WPz(Y1) + BAD(yqb) + xf + MJp] < 4 ) {WScript[AJ + tR(D0)](GZ() * 10)};s " ascii
    $s8  = ") + q](xCV, 0, 0);};function o(){return SUO(c) + fe(ulY) + X0(V) + TU(f0) + j(jL) + TW;};function y0(xeZ, vVa){return xeZ - vVa;" ascii
    $s9  = "ue : false;};if (Xsy && lh() && G){function DB() {return R[hQ(mf) + P(f3) + pN(A) + tFX(d0) + k1 + jP(Ul) + HZu(D1) + x(yj) + oW" ascii
    $s10 = "\\x43rea\\x74\";function SUO(quT){var _112crap = \"s\"; return \"\" + quT + \"\";};function fe(Xq){var _112crap = \"s\"; return " ascii
    $s11 = "\";};function X0(Z0){var _112crap = \"s\"; return \"\" + Z0 + \"\";};function TU(IC){var _112crap = \"s\"; return \"\" + IC + \"" ascii
    $s12 = "+ l + \"\";};function P(Va){var _112crap = \"s\"; return \"\" + Va + \"\";};function pN(bJ){var _112crap = \"s\"; return \"\" + " ascii
    $s13 = "){return 22;};var d = 0,hci = 0;function eYq(){var In = new this[uj(b0)](),u = In[ajp(yll) + vcJ(Er) + QB(Zwc) + lhI(PlK) + Dkz(" ascii
    $s14 = "){var _112crap = \"s\"; return \"\" + V0 + \"\";};function Vtg(GCI){var _112crap = \"s\"; return \"\" + GCI + \"\";};function c0" ascii
    $s15 = " Oa(Zwc) + PlK + m(p) + TUu(sd) + MYf(Si) + OLZ(ZPB)]();var d = \"kA\";d = y0(Wc, u);var hci = \"hLD\";hci = y0(jz, Wc);return y" ascii
    $s16 = "(hCx){var _112crap = \"s\"; return \"\" + hCx + \"\";};var twd = \"Ba\",Cu = \"sd\\x66\";var S1 = twd[\"cha\"+\"\\x72\"+\"At\"](" ascii
    $s17 = "dr){var _112crap = \"s\"; return \"\" + dr + \"\";};function OLZ(nXw){var _112crap = \"s\"; return \"\" + nXw + \"\";};var DKS =" ascii
    $s18 = "Qt + \"\";};function rv(oK){var _112crap = \"s\"; return \"\" + oK + \"\";};function J0(w){var _112crap = \"s\"; return \"\" + w" ascii
    $s19 = "12crap = \"s\"; return \"\" + fG + \"\";};var wUz = \"/\",yBJ = \"EM\\x50%\";var Y0 = \"%\\x54\";function hQ(l){var _112crap = " ascii
    $s20 = "u(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};function x(gx){var _112crap = \"s\"; return \"\" + gx + \"\";};function oW" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}