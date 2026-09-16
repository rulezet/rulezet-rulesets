rule sig_20160323_31243b95fda8eeae51d654c118ec0adb {
  meta:
    description = "datamaliciousorder - file 20160323_31243b95fda8eeae51d654c118ec0adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3d83f250f9c7896ed13132f10bc83d88d1b725b8981a6809c535d36ff75a89"

  strings:
    $s1  = " \"ct\",c = \"j\\x65\";var Lz = \"Ob\",j = \"te\";var d = \"a\",VT = \"Cre\";var A0 = false,C = function Jgm() {return WScript[x" ascii
    $s2  = " + fSK(L1) + Km, false);R[yxI(gc) + eGx(R1)]();while (R[Sku + Grp(ur0) + jP(pqe)] < 4 ) {WScript[Xx(NOT) + g](Pl() * 10)};y = fa" ascii
    $s3  = "aw = 0,kam = 0;function W(){var VUZ = new this[kb(ko)](),kw = VUZ[gYv + PlI(x1) + GKJ + C0(CT) + u(a)]();WScript[l0(NOT) + g](Pl" ascii
    $s4  = "());var VUZ = new this[ko](),vYz = VUZ[P(gYv) + RY(x1) + GKJ + CT + QOD(a)]();WScript[NOT + L(g)](Pl());var VUZ = new this[Gg(ko" ascii
    $s5  = " return mDz;};aw = (yRM) ? 14134 : 414234;r = WScript[oIC()](kwf + Zcp + Z0 + OQo(Fth));iu = r;kam = (n) ? aw : kam;iu[(kD(O1) +" ascii
    $s6  = "ac(){return fRx(PKL) + kWy(wRm) + Hxo(xor) + W0(j0) + e(h);};function A(Xd, z){return Xd - z;};function oIC(){return D0(VT) + x0" ascii
    $s7  = "123313 * aw + kam; n = true; kam = \"07t9gasdf76ags\" + 123313 * aw + kam; break;}}function M() {return ((yRM == n) && (yRM == t" ascii
    $s8  = "e)) ? true : false;};if (yRM && M() && n){function v() {return C[gUZ(dH) + O0 + qB(G0) + C1(N1) + w0(TJX) + qL(NjY) + d1(tJ) + Q" ascii
    $s9  = "function ctj(d3){var _112crap = \"s\"; return \"\" + d3 + \"\";};function fEY(eJS){var _112crap = \"s\"; return \"\" + eJS + \"" ascii
    $s10 = "aw, kam);}var yRM = false,n = false;for (var UUf = 0; UUf < Pl() * 1; UUf++){if (W() != 0){yRM = true; kam = \"07t9gasdf76ags\" " ascii
    $s11 = " _112crap = \"s\"; return \"\" + dug + \"\";};function RR(fJ){var _112crap = \"s\"; return \"\" + fJ + \"\";};function kD(Ltp){v" ascii
    $s12 = "\" + iJi + \"\";};function QOD(Tt){var _112crap = \"s\"; return \"\" + Tt + \"\";};function Dw(iQc){var _112crap = \"s\"; return" ascii
    $s13 = "[\"cha\"+\"\\x72\"+\"At\"](3),N = tMV[\"cha\"+\"\\x72\"+\"At\"](3);var G = \"WS\\x63ri\";function xS(wC){var _112crap = \"s\"; r" ascii
    $s14 = "112crap = \"s\"; return \"\" + ja + \"\";};function jP(Jn){var _112crap = \"s\"; return \"\" + Jn + \"\";};var QC = \"kFQQsZS\"," ascii
    $s15 = "x65\";var ur0 = QC[\"cha\"+\"\\x72\"+\"At\"](4),Sku = \"rea\\x64y\";function yxI(fm){var _112crap = \"s\"; return \"\" + fm + \"" ascii
    $s16 = "};function DR(oS){var _112crap = \"s\"; return \"\" + oS + \"\";};function Ir(pm){var _112crap = \"s\"; return \"\" + pm + \"\";" ascii
    $s17 = " _112crap = \"s\"; return \"\" + Evg + \"\";};var RSf = \"fda\\x66\\x61\",LJO = \"a\";function y1(T){var _112crap = \"s\"; retur" ascii
    $s18 = "ar _112crap = \"s\"; return \"\" + WrF + \"\";};function D0(U){var _112crap = \"s\"; return \"\" + U + \"\";};function x0(X){var" ascii
    $s19 = " \"t\\x72e\\x61\";var Zcp = \"\\x4fDB.\\x53\",kwf = \"AD\";function sGr(yp){var _112crap = \"s\"; return \"\" + yp + \"\";};func" ascii
    $s20 = "unction i(On){var _112crap = \"s\"; return \"\" + On + \"\";};var C2 = \"x\\x65\",ur = \"Hp\\x35.e\";var HS = \"oDx0C\",yk = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}