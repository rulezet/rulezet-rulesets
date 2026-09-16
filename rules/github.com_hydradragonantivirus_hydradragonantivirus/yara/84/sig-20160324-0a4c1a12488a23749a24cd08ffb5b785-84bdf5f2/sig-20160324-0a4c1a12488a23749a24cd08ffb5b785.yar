rule sig_20160324_0a4c1a12488a23749a24cd08ffb5b785 {
  meta:
    description = "datamaliciousorder - file 20160324_0a4c1a12488a23749a24cd08ffb5b785.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d63829e099143e780a57764ba6e98e28117da6942ecbf2067cf4370ff49c66"

  strings:
    $s1  = ") + D(Z0)](),Kjs = pA[CQU(omK) + fG + we(CJ) + L0(wY) + n0(z0)]();WScript[y0(y)](whe());var pA = new this[rVS + Z0](),M = pA[qc(" ascii
    $s2  = "urn WScript[twH(te) + uXd(dyc) + z(q)](DaB(fp) + sQ(vjG) + V(L));}();function fuP(JeJ){FX[O0(n) + SG](JeJ, 0, 0);};function rdE(" ascii
    $s3  = "omK) + E(fG) + uc(CJ) + wY + Af(z0)]();WScript[vNu(y)](whe());var pA = new this[SA(rVS) + Mm(Z0)](),Rvp = pA[jV(omK) + dpv(fG) +" ascii
    $s4  = "or(tiO) + G(n2) + K(C1);}; m = rdE(); Rdd = WScript[l(te) + dyc + wU(q)](m); var Z = true; while (Z){try {Rdd[Q](uDj, Oi + n3(fu" ascii
    $s5  = "){return I0 + is + cFX + YJ(q0);};function O(WR, Yx){return WR - Yx;};function Iv(){return I(te) + dyc + q;};/*@cc_on  @if (@_wi" ascii
    $s6  = "kZ && WF() && FPB){function sJs() {return FX[C0(NGl) + lnl + hta(ZNs) + Ye + n1 + I1](Mo + c + p0(p) + dLX(ObT)) + p1 + RD(s) + " ascii
    $s7  = "Px = \"07t9gasdf76ags\" + 123313 * qIf + gPx; break;}}function WF() {return ((QkZ == FPB) && (QkZ == true)) ? true : false;};if " ascii
    $s8  = "x + eRF(aKe) + xkF(FcN) + bb(mtd)] < 4 ) {WScript[h(y)](whe() * 10)};Z = false;} catch(M0){Z = (O3(jO) + uq(qu), i0 + CU(U2) + C" ascii
    $s9  = "function BmR(GN){var _112crap = \"s\"; return \"\" + GN + \"\";};function jxP(ZL){var _112crap = \"s\"; return \"\" + ZL + \"\";" ascii
    $s10 = "\\x73\\x65\",IT = \"\\x63\\x6co\";function EH(WNv){var _112crap = \"s\"; return \"\" + WNv + \"\";};function sq(D1){var _112crap" ascii
    $s11 = "lse;for (var Ih = 0; Ih < whe() * 1; Ih++){if (Zl() != 0){QkZ = true; gPx = \"07t9gasdf76ags\" + 123313 * qIf + gPx; FPB = true;" ascii
    $s12 = " \"\";};function Onn(Xod){var _112crap = \"s\"; return \"\" + Xod + \"\";};function YUq(jnH){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = " DTd(CJ) + wY + z0]();var qIf = \"Vsw\";qIf = O(M, Kjs);var gPx = \"H\";gPx = O(Rvp, M);return O(qIf, gPx);}var QkZ = false,FPB " ascii
    $s14 = "function mVO(z3){var _112crap = \"s\"; return \"\" + z3 + \"\";};function Tfh(M2){var _112crap = \"s\"; return \"\" + M2 + \"\";" ascii
    $s15 = " dc + \"\";};var S0 = \"d\\x79\",VNv = \"o\";var cbt = \"nseB\",FqU = \"spo\";var p2 = \"Re\";function DtX(V0){var _112crap = \"" ascii
    $s16 = "= \"s\"; return \"\" + G0 + \"\";};var O2 = \"ktV5\",U1 = \"XXAs\";var pt0 = U1[\"c\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](3),o = " ascii
    $s17 = "U + \"\";};function uXd(QHb){var _112crap = \"s\"; return \"\" + QHb + \"\";};function z(SK){var _112crap = \"s\"; return \"\" +" ascii
    $s18 = "= \"TE\\x4d\";var Mo = I2[\"c\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](3);function C0(Fu){var _112crap = \"s\"; return \"\" + Fu + \"" ascii
    $s19 = ";function Af(C){var _112crap = \"s\"; return \"\" + C + \"\";};function jV(dd){var _112crap = \"s\"; return \"\" + dd + \"\";};f" ascii
    $s20 = "ar _112crap = \"s\"; return \"\" + CI + \"\";};var tFM = \"fa\",Zr = \"\\x64a\";var gJ = \"af\";function CU(pT){var _112crap = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}