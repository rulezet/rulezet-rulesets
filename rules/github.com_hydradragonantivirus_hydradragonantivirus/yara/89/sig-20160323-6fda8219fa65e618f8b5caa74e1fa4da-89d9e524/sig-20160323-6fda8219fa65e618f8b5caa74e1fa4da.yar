rule sig_20160323_6fda8219fa65e618f8b5caa74e1fa4da {
  meta:
    description = "datamaliciousorder - file 20160323_6fda8219fa65e618f8b5caa74e1fa4da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86c1f154d6961b453097e6f4b5c41d56ae27f26130846a6044115c3a7ec98efc"

  strings:
    $s1  = "function sZ0(Qa){var _112crap = \"s\"; return \"\" + Qa + \"\";};var K1 = \"\\x65\",oU = \"c\\x6cos\";function Qu(xj){var _112cr" ascii
    $s2  = "RaK = \"//\\x66\";var A = \"ht\\x74p:\";function QEy(nP){var _112crap = \"s\"; return \"\" + nP + \"\";};var WVV = \"GE\\x54\";f" ascii
    $s3  = ";}; O = g(); h = WScript[FG(YJW) + J(eW) + Hnd + eS(s)](O); var la = true; while (la){try {h[e2(i1)](QEy(WVV), A + k0(RaK) + Le(" ascii
    $s4  = "= function ZKg() {return WScript[TBQ(YJW) + x0(eW) + Hnd + s](gw + lBD + T0);}();function xID(B){T[rA(mb)](B, 0, 0);};function g" ascii
    $s5  = "(w)](Qww());var YF = new this[IzL(F) + Csl(B1)](),x = YF[Bg(IwU) + rw(e1) + S(sP) + I(E1) + QZ + b0(DC) + p]();WScript[M(FB) + D" ascii
    $s6  = "Rg(){var YF = new this[gYS(F) + ADE(B1)](),b = YF[Xa(IwU) + e1 + KN(sP) + qsQ(E1) + QZ + oAS(DC) + BJj(p)]();WScript[hO(FB) + lt" ascii
    $s7  = "\",E1 = \"Mil\";var sP = \"T\\x43\",e1 = \"\\x55\";var IwU = \"get\";function gYS(fTh){var _112crap = \"s\"; return \"\" + fTh +" ascii
    $s8  = "(){return fT + e0 + Q(gN) + J0(Hfr) + G0(El);};function cj(u0, RHa){return u0 - RHa;};function sn(){return E(YJW) + BIv(eW) + Y(" ascii
    $s9  = "n zr() {return ((kHD == ss) && (kHD == true)) ? true : false;};if (kHD && zr() && ss){function i() {return T[L0(Oqn) + yEz + sK(" ascii
    $s10 = ") + Nwi(Hn)] < 4 ) {WScript[O2(FB) + w](Qww() * 10)};la = false;} catch(iu){la = (G3(F1) + jX(Z0) + nfc(ltR), g1(F2) + I1(beC) +" ascii
    $s11 = " \"\" + G + \"\";};var mb = \"\\x52\\x75n\",T0 = \"e\\x6c\\x6c\";var lBD = \"\\x70t\\x2eSh\",gw = \"\\x57Scri\";function TBQ(ylr" ascii
    $s12 = "(5);var tPU = \"nse\\x42o\",ngK = \"o\";var VMf = \"R\\x65s\\x70\";function oR(pZ){var _112crap = \"s\"; return \"\" + pZ + \"\"" ascii
    $s13 = " = \"\\x6fn\",luf = \"iti\";var XS = \"pos\";function Oa(tsl){var _112crap = \"s\"; return \"\" + tsl + \"\";};function vLV(P0){" ascii
    $s14 = "SfmhK3Y\",Wlu = NK[\"char\"+\"\\x41\"+\"t\"](2);var beC = \"fasd\",F2 = \"fad\";function G3(b3){var _112crap = \"s\"; return \"" ascii
    $s15 = "\"\" + v0 + \"\";};function IV(YX){var _112crap = \"s\"; return \"\" + YX + \"\";};function bZO(NrF){var _112crap = \"s\"; retur" ascii
    $s16 = "ction Tx(yhV){var _112crap = \"s\"; return \"\" + yhV + \"\";};function Fp(i2){var _112crap = \"s\"; return \"\" + i2 + \"\";};v" ascii
    $s17 = "function sZ0(Qa){var _112crap = \"s\"; return \"\" + Qa + \"\";};var K1 = \"\\x65\",oU = \"c\\x6cos\";function Qu(xj){var _112cr" ascii
    $s18 = ";function FG(rp){var _112crap = \"s\"; return \"\" + rp + \"\";};function J(obn){var _112crap = \"s\"; return \"\" + obn + \"\";" ascii
    $s19 = "mdw) + Ib(Ga) + Fg(OJR) + obw + jae(iYv) + MFS(J1) + BeX(ErU), false);h[QTr(kdO)]();while (h[L1(f1) + ht(nTg) + p1(SsP) + PIm(LI" ascii
    $s20 = "= \"s\"; return \"\" + P0 + \"\";};var Ia = \"D9VoTdMs\",BH = \"FE0Uxyrbdz7\";var oT = BH[\"char\"+\"\\x41\"+\"t\"](5),QT = Ia[" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}