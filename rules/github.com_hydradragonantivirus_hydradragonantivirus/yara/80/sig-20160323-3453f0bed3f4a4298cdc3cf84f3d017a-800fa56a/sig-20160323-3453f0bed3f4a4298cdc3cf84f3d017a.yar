rule sig_20160323_3453f0bed3f4a4298cdc3cf84f3d017a {
  meta:
    description = "datamaliciousorder - file 20160323_3453f0bed3f4a4298cdc3cf84f3d017a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f250342a7a570bd76b629411558433495f0a2c837b245b2818d29ce765621455"

  strings:
    $s1  = "= a[v(z0) + ABT + wB(eqb) + dfw(n) + iM]();WScript[c0 + C0(Y) + je(n0)](hN());var a = new this[fS(i0)](),Pl = a[JAb(z0) + PGH(AB" ascii
    $s2  = "turn WScript[Rq + Bt(i) + Rk + Td(Hj)](aJ(rb) + rf + r + EL(cT));}();function jx(shZ){a0[wCT(Co)](shZ, 0, 0);};function I(){retu" ascii
    $s3  = "function Nl(dq){var _112crap = \"s\"; return \"\" + dq + \"\";};function U2(dU){var _112crap = \"s\"; return \"\" + dU + \"\";};" ascii
    $s4  = "r a = new this[i0](),g = a[z0 + ABT + va(eqb) + n + qe(iM)]();WScript[qH(c0) + yfJ(Y) + fl(n0)](hN());var a = new this[i0](),Zh " ascii
    $s5  = "rn K1(C) + k(c) + dUR(XW) + M0 + yyH(kaj) + pZ(q);};function Z(lGu, z){return lGu - z;};function Ai(){return Rq + i + B(Rk) + Hj" ascii
    $s6  = "9gasdf76ags\" + 123313 * lx + SY; break;}}function sY() {return ((udG == lo) && (udG == true)) ? true : false;};if (udG && sY() " ascii
    $s7  = "alse);gY[WC(S0)]();while (gY[vW(Nx) + Lz + rMG + H] < 4 ) {WScript[jq(c0) + Y + n0](hN() * 10)};Dh = false;} catch(VnQ){Dh = (ko" ascii
    $s8  = "= \"XML\\x32\";var C = \"\\x4dS\";function wCT(ysm){var _112crap = \"s\"; return \"\" + ysm + \"\";};var Co = \"\\x52un\";functi" ascii
    $s9  = "v(pVe) + DtB, Vw(yt) + lNb + Nf0 + Nib + H0, X1(iZ) + ngo(XrV), true);};}function pC(vDN) {var Yq = (1, 2, 3, 4, 5, vDN); return" ascii
    $s10 = "ction sH(jI){var _112crap = \"s\"; return \"\" + jI + \"\";};function p1(LrH){var _112crap = \"s\"; return \"\" + LrH + \"\";};f" ascii
    $s11 = "12crap = \"s\"; return \"\" + s + \"\";};function EL(mHH){var _112crap = \"s\"; return \"\" + mHH + \"\";};var cT = \"\\x68ell\"" ascii
    $s12 = "\"; return \"\" + Cq + \"\";};function yBh(aM){var _112crap = \"s\"; return \"\" + aM + \"\";};var cUU = \"on\",IBO = \"osi\\x74" ascii
    $s13 = "& lo){function wXU() {return a0[W0(Bvn) + n1(j) + a1 + tP + rfE(T) + I0(nS) + TIL(xjx) + Ff(d0) + p0 + BG(z2) + kD(Pn) + NiN(X0)" ascii
    $s14 = "crap = \"s\"; return \"\" + cdP + \"\";};function I0(L){var _112crap = \"s\"; return \"\" + L + \"\";};function TIL(nzX){var _11" ascii
    $s15 = "lse;for (var P = 0; P < hN() * 1; P++){if (Vl() != 0){udG = true; SY = \"07t9gasdf76ags\" + 123313 * lx + SY; lo = true; SY = \"" ascii
    $s16 = "W = \"0\";function s0(bU){var _112crap = \"s\"; return \"\" + bU + \"\";};function U(VL){var _112crap = \"s\"; return \"\" + VL " ascii
    $s17 = "ar O0 = nAe[\"charA\"+\"\\x74\"+\"\"](0),W1 = \"\\x53\";function vW(CVE){var _112crap = \"s\"; return \"\" + CVE + \"\";};var H " ascii
    $s18 = "Zs){var _112crap = \"s\"; return \"\" + jZs + \"\";};var CIY = \".ex\\x65\",zuc = \"np4BP\";var e0 = \"a\\x59K\\x4b\",BDl = \"2K" ascii
    $s19 = " + fH + \"\";};function L1(GE){var _112crap = \"s\"; return \"\" + GE + \"\";};function G0(U0){var _112crap = \"s\"; return \"\"" ascii
    $s20 = "(K3){var _112crap = \"s\"; return \"\" + K3 + \"\";};function V(nn){var _112crap = \"s\"; return \"\" + nn + \"\";};var o = \"2S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}