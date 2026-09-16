rule sig_20160324_69d7f5f6285d6ff3aac8c47aa131e52b {
  meta:
    description = "datamaliciousorder - file 20160324_69d7f5f6285d6ff3aac8c47aa131e52b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5fb97f2e25adc5fe2767aec54bd4ddd22b330457fd60fba7e00e9cf98404c6e"

  strings:
    $s1  = "ect\";var Q1 = function HRG() {return WScript[QX](z + a + MRX);}();var Bn = 123213,omo = \"MSXML2.XMLHTTP\";var Xv = 2123213,Tb " ascii
    $s2  = " + Sz]();WScript[hA](VWV());var N = new this[mgC](),O0 = N[uC + ky(aBO) + H + Sz]();var iyT = \"EY\";iyT = DPG(Fn, Go);var J = " ascii
    $s3  = "QJ + x2, g + W, 2);};}function L(pD) {var Pis = (1, 2, 3, 4, 5, pD); return Pis;};NG = WScript[M()](Otw + F(N1) + G);Oa = NG;Oa[" ascii
    $s4  = "this[ivh(mgC)](),Go = N[uC + N0(aBO) + H + nF(Sz)]();WScript[m0(hA)](VWV());var N = new this[mgC](),Fn = N[j0(uC) + Bdr(aBO) + H" ascii
    $s5  = " EoU + AUx + NCN;}; Oa = oK(); x = WScript[QX](Oa); var ko = 1; while (ko){try {x[B0](JlZ, DpM + DJy(CvR) + c1 + e0 + Pm + hXZ(w" ascii
    $s6  = "var HoR = \"c\\x6cose\";function XT(v){var _112crap = \"s\"; return \"\" + v + \"\";};function bB(xr){var _112crap = \"s\"; retu" ascii
    $s7  = ";function O(P){Q1[Gk](P, Tb, Tb);};function oK(){return omo;};function DPG(eO, m){return eO - m;};function M(){return QX;};/*@cc" ascii
    $s8  = " == true) && (e == VH)) ? 1 : Tb;};if (e && OqL() && VH){function lXd() {return Q1[x0(J1) + pe + s0 + c0(yi) + iAH](o(Y) + rR) +" ascii
    $s9  = ") + Ybl, false);x[Pgz]();n = \"Sleep\";while (x[jWZ + Hxu] < 4 ) {WScript[n](VWV() * 10)};ko = Tb;} catch(yx){ko = (aRc + zQ(x1)" ascii
    $s10 = "\\x65\\x61\\x64\\x79\";var vS = \"\\x70\",dNh = \"S\\x6cee\";var Pgz = \"\\x73end\";function DJy(b0){var _112crap = \"s\"; retur" ascii
    $s11 = " J = \"07t9gasdf76ags\" + 123313 * iyT + J; VH = true; J = \"07t9gasdf76ags\" + 123313 * iyT + J; break;}}function OqL() {return" ascii
    $s12 = "urn \"\" + hNn + \"\";};var n0 = \"\\x65\",ny = \"w\\x72\\x69t\";var GA = \"\\x74ype\",C = \"\\x6fpen\";function F(q){var _112cr" ascii
    $s13 = "\";function m0(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};var hA = \"S\\x6cee\\x70\";function N0(CxB){var _112crap = \"" ascii
    $s14 = " \"n\\x64s\",H = \"i\\x73e\\x63o\";var aBO = \"CM\\x69\\x6c\\x6c\",uC = \"ge\\x74UT\";function ivh(OxV){var _112crap = \"s\"; re" ascii
    $s15 = ";var NCN = \"3\\x2e\\x65\\x78e\",AUx = \"\\x73siQ\";var EoU = \"\\x32\\x55\\x61U\";function o(B){var _112crap = \"s\"; return \"" ascii
    $s16 = " rR = \"\\x25/\",Y = \"%T\\x45MP\";function x0(Ykc){var _112crap = \"s\"; return \"\" + Ykc + \"\";};function c0(bh){var _112cra" ascii
    $s17 = "x66a\";function zQ(by){var _112crap = \"s\"; return \"\" + by + \"\";};var x1 = \"\\x61\",aRc = \"a\\x73\\x64f\";var Hxu = \"sta" ascii
    $s18 = "m\";J = DPG(O0, Fn);return DPG(iyT, J);}var e = false,VH = false;for (var Q0 = Tb; Q0 < VWV() * 1; Q0++){if (Q() != Tb){e = true" ascii
    $s19 = "+ \"\";};var df = \"\\x65\",Np = \"oFi\\x6c\";var YD = \"S\\x61\\x76eT\";function cWg(s1){var _112crap = \"s\"; return \"\" + s1" ascii
    $s20 = ";};function Bdr(sos){var _112crap = \"s\"; return \"\" + sos + \"\";};function ky(d){var _112crap = \"s\"; return \"\" + d + \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}