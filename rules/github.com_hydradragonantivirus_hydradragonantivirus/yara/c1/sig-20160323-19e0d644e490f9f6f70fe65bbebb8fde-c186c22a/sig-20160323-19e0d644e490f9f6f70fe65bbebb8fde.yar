rule sig_20160323_19e0d644e490f9f6f70fe65bbebb8fde {
  meta:
    description = "datamaliciousorder - file 20160323_19e0d644e490f9f6f70fe65bbebb8fde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "751dd90a6b7938b8524b6c0e9175cd4d2797a4b934bb81e36190124f906c1e05"

  strings:
    $s1  = ";var MK = \"ct\",Sh = \"je\";var s = \"at\\x65\\x4fb\",Bo = \"Cre\";var M0 = false,Ny = function EY() {return WScript[Ko(Bo) + H" ascii
    $s2  = "function DS(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function nCW(QW){var _112crap = \"s\"; return \"\" + QW + \"\";}" ascii
    $s3  = "c)) + K(EYo) + WOm(Wa) + YZ + cf(a1) + am(Wn);}; V = dzT(); ls = WScript[Ou(Bo) + I(s) + Sh + c(MK)](V); var gd = true; while (g" ascii
    $s4  = "[qdX(yQ)](),E = VH[Mu(iEB) + qyL(WHn) + dRo(Hne) + nr(I0) + GM]();WScript[KIn](ME());var VH = new this[UK(yQ)](),zB = VH[iEB + r" ascii
    $s5  = "0(WHn) + B(Hne) + z(I0) + GM]();WScript[KIn](ME());var VH = new this[EQP(yQ)](),q = VH[ppc(iEB) + WHn + mw(Hne) + Vp(I0) + ce(GM" ascii
    $s6  = "x43\";var iEB = \"getUT\";function qdX(W){var _112crap = \"s\"; return \"\" + W + \"\";};function UK(TUw){var _112crap = \"s\"; " ascii
    $s7  = "J) + RH(P0) + sK(e0) + Ti(r);};function qJ(jIA, Bp){return jIA - Bp;};function u(){return Bo + v(s) + Sh + XPK(MK);};/*@cc_on  @" ascii
    $s8  = "313 * O + vvT; break;}}function iXz() {return ((E0 == SH) && (E0 == true)) ? true : false;};if (E0 && iXz() && SH){function e() " ascii
    $s9  = "v), false);ls[gdn]();while (ls[eDB + CKu(x) + N1 + lpI(T1)] < 4 ) {WScript[zQ(KIn)](ME() * 10)};gd = false;} catch(JJ){gd = (oJM" ascii
    $s10 = "llis\",g = \"\\x55T\\x43Mi\";var b = \"get\",XIb = \"pN1cQev\";var p = XIb[\"c\"+\"\\x68\"+\"a\"+\"\\x72\"+\"At\"](5),F = \"Da" ascii
    $s11 = "n Ko(wQM){var _112crap = \"s\"; return \"\" + wQM + \"\";};function HrB(fl){var _112crap = \"s\"; return \"\" + fl + \"\";};func" ascii
    $s12 = "1fda\";function d1(kYQ){var _112crap = \"s\"; return \"\" + kYQ + \"\";};var z1 = \"3TdE\",Ml = \"f\";var eb = z1[\"c\"+\"\\x68" ascii
    $s13 = "n Ng(GfW){var _112crap = \"s\"; return \"\" + GfW + \"\";};function h2(cxW){var _112crap = \"s\"; return \"\" + cxW + \"\";};fun" ascii
    $s14 = "BN0eiq\",B1 = Mc[\"c\"+\"\\x68\"+\"a\"+\"\\x72\"+\"At\"](4);var Afe = \"clos\";function a4(KQ){var _112crap = \"s\"; return \"\"" ascii
    $s15 = "var _112crap = \"s\"; return \"\" + nF + \"\";};var ud = \"fueHx\",VQR = \"y\";var pqL = \"\\x65\\x42o\\x64\",B0 = \"\\x6e\\x73" ascii
    $s16 = "var _112crap = \"s\"; return \"\" + pc + \"\";};function mcx(R){var _112crap = \"s\"; return \"\" + R + \"\";};var pDV = \"Mrb\"" ascii
    $s17 = "_112crap = \"s\"; return \"\" + u0 + \"\";};function wEB(FZp){var _112crap = \"s\"; return \"\" + FZp + \"\";};var ReM = \"YvZnk" ascii
    $s18 = "f < ME() * 1; Hyf++){if (M() != 0){E0 = true; vvT = \"07t9gasdf76ags\" + 123313 * O + vvT; SH = true; vvT = \"07t9gasdf76ags\" +" ascii
    $s19 = "{return Ny[o(vwp) + b0(G) + P1(bv) + d0 + qLk + UUM(jjZ) + md(p0) + ZvZ(obK) + TP(XnA) + f0(vu) + wEB(KyB)](cvB + bPJ(Ok) + cg(T" ascii
    $s20 = " \"\" + N + \"\";};function I(jR){var _112crap = \"s\"; return \"\" + jR + \"\";};function c(vQ){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}