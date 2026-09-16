rule sig_20160323_abad20fe8eb182883aa428d51920fb40 {
  meta:
    description = "datamaliciousorder - file 20160323_abad20fe8eb182883aa428d51920fb40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163e94a8aae5130e360e09dd177e181fe066735c6c73164b22f0c3033426691d"

  strings:
    $s1  = "function E1(xju){var _112crap = \"s\"; return \"\" + xju + \"\";};function q4(rUc){var _112crap = \"s\"; return \"\" + rUc + \"" ascii
    $s2  = "0 + InP(etx) + QgK + jJ(F)]();WScript[iZg(H0) + Bd](LNK());var pnw = new this[zmh(wn) + MHW(Z0) + Q(Esd)](),Gwa = pnw[wu(q) + z(" ascii
    $s3  = "1) + Pg(B0), false);e[Gx(UX) + pAr + cz(bQ)]();while (e[Id(t0) + qK(C2) + Zp(Dz)] < 4 ) {WScript[rdI(H0) + Bd](LNK() * 10)};W = " ascii
    $s4  = ") + Z1(F)]();WScript[kn(H0) + Bd](LNK());var pnw = new this[H(wn) + WTd(Z0) + e0(Esd)](),w = pnw[q + xc0(KLn) + uNF(IX) + nw + q" ascii
    $s5  = "on Um() {return WScript[w0(qo) + qC(nbK) + ouS(g)](jVU(DMJ) + k + bs(pw) + Y(Qoa) + On(g0));}();function qv(EHO){Pr[el(L0) + d0]" ascii
    $s6  = "Cx[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](1),q = \"getU\";function Gb(vt){var _112crap = \"s\"; return \"\" + vt " ascii
    $s7  = "(EHO, 0, 0);};function L(){return j(ThR) + IF(b) + OF(I1) + GvH(Eg);};function l(J, uiN){return J - uiN;};function vDB(){return " ascii
    $s8  = "13 * gN + zBX; xc = true; zBX = \"07t9gasdf76ags\" + 123313 * gN + zBX; break;}}function I() {return ((iO == xc) && (iO == true)" ascii
    $s9  = "? true : false;};if (iO && I() && xc){function V() {return Pr[ly + hv(BR) + YhR(uF) + l0(uhD) + igR(YGi) + pf(BJm) + L3(nPR) + D" ascii
    $s10 = "\\x65\\x54\";var i1 = B1[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](0);function Z6(D2){var _112crap = \"s\"; return " ascii
    $s11 = "\\x4d\",ThR = \"MSXML\";function el(yJ){var _112crap = \"s\"; return \"\" + yJ + \"\";};var zBd = \"zFDnAjy\",d0 = zBd[\"\"+\"" ascii
    $s12 = "KqG); var W = true; while (W){try {e[W1(fVv) + KQE(B) + C1(q2)](MAR(T1), os + m(p0) + Bn(S0) + go + v1(z1) + Sh(Z3) + czW + Ta(j" ascii
    $s13 = "+\"\\x41\"+\"t\"](5);var pAr = \"\\x6e\",UX = \"s\\x65\";function m(ARl){var _112crap = \"s\"; return \"\" + ARl + \"\";};functi" ascii
    $s14 = " _112crap = \"s\"; return \"\" + PcD + \"\";};function ivs(EX){var _112crap = \"s\"; return \"\" + EX + \"\";};var QCx = \"PT\"," ascii
    $s15 = "+ D1 + \"\";};var NC = \"eBo\\x64y\",mla = \"\\x6es\";var shf = \"es\\x70\\x6f\",I3 = \"\\x52\";function JeR(Nv){var _112crap = " ascii
    $s16 = "12crap = \"s\"; return \"\" + PB + \"\";};function IF(amn){var _112crap = \"s\"; return \"\" + amn + \"\";};function OF(skm){var" ascii
    $s17 = "= \"s\"; return \"\" + sA + \"\";};function e0(C){var _112crap = \"s\"; return \"\" + C + \"\";};function zmh(Yws){var _112crap " ascii
    $s18 = "Wy + \"\";};function y(w1){var _112crap = \"s\"; return \"\" + w1 + \"\";};function Ed(d){var _112crap = \"s\"; return \"\" + d " ascii
    $s19 = " KNn(pBd){var _112crap = \"s\"; return \"\" + pBd + \"\";};function ku(Q3){var _112crap = \"s\"; return \"\" + Q3 + \"\";};var L" ascii
    $s20 = ";function stk(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};var eL = \"qMseza\",Aa = eL[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"ar" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}