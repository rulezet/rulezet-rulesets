rule sig_20160324_00df1e86838f58c521c62a342f19050e {
  meta:
    description = "datamaliciousorder - file 20160324_00df1e86838f58c521c62a342f19050e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03e4a01c8085c6dde81fbcf0209f8902664181533667a2c1af1adea4ddf37459"

  strings:
    $s1  = "function d1(aKB){var _112crap = \"s\"; return \"\" + aKB + \"\";};var Ve = \"c\\x6cose\",r = \"\\x6ce\";var s0 = \"T\\x6fFi\",T " ascii
    $s2  = "teObject\",Nh = function VY() {return WScript[qb](xD(W0) + KZ + Y + ASz);}();var ouY = 123213,yo = \"MSXML2.XMLHTTP\";var Pv = 2" ascii
    $s3  = " l0 + mQ + Cvv + Y0](L0 + Juj) + IEV(UGZ) + XHw + yVR;}; am = w(); mzj = WScript[qb](am); var Jpe = 1; while (Jpe){try {mzj[aa](" ascii
    $s4  = "Mbg); return yx;};uvL = WScript[GU()](dtg + pd(Lmd) + Ka);am = uvL;am[(aa)]();am[Vei] = v(1);am[EHi](mzj[S + P + jV]);am[i0 + dr" ascii
    $s5  = "rf, tGn(z) + H + n + B0(Heb) + Jn(PW) + QLR + qZh + UO, false);mzj[s(Ho)]();Va = \"Sleep\";while (mzj[Q + Gj] < 4 ) {WScript[Va]" ascii
    $s6  = "= id[go + q + g + WmM + mz(b)]();WScript[jv](PHO());var id = new this[El](),dh = id[go + q + g + WmM + b]();var p = \"o\";p = SN" ascii
    $s7  = "tion Or(){var id = new this[i(El)](),lk = id[go + gXd(q) + d(g) + WmM + b]();WScript[jv](PHO());var id = new this[VT(El)](),ypi " ascii
    $s8  = "213,Lar = 0;function m(u){Nh[pvw(wMl)](u, Lar, Lar);};function w(){return yo;};function SN(W, lse){return W - lse;};function GU(" ascii
    $s9  = "function ddd() {return ((KA == true) && (KA == v0)) ? 1 : Lar;};if (KA && ddd() && v0){function qT() {return Nh[fkh + eUK(eCI) +" ascii
    $s10 = "\\x48T\",rd = \"\\x4c2.\\x58\";var fp = \"MSX\\x4d\";function xD(qf){var _112crap = \"s\"; return \"\" + qf + \"\";};var ASz = " ascii
    $s11 = "\\x54\",aa = \"ope\\x6e\";function IEV(zBT){var _112crap = \"s\"; return \"\" + zBT + \"\";};var yVR = \"e\\x78e\",XHw = \"c\\x6" ascii
    $s12 = "UGZ = \"dzaR\\x57\",Juj = \"\\x50\\x25\\x2f\";var L0 = \"%TE\\x4d\";function eUK(ly){var _112crap = \"s\"; return \"\" + ly + \"" ascii
    $s13 = "crap = \"s\"; return \"\" + qzj + \"\";};function Jn(Du){var _112crap = \"s\"; return \"\" + Du + \"\";};var UO = \"a\\x73\",qZh" ascii
    $s14 = "var El = \"Dat\\x65\";function pvw(FDS){var _112crap = \"s\"; return \"\" + FDS + \"\";};var wMl = \"\\x52un\",QWs = \"\\x54P\";" ascii
    $s15 = "n mz(oN){var _112crap = \"s\"; return \"\" + oN + \"\";};var b = \"\\x73\",WmM = \"\\x63ond\";var g = \"lli\\x73e\",q = \"T\\x43" ascii
    $s16 = "function d1(aKB){var _112crap = \"s\"; return \"\" + aKB + \"\";};var Ve = \"c\\x6cose\",r = \"\\x6ce\";var s0 = \"T\\x6fFi\",T " ascii
    $s17 = "65e\\x70\";function gXd(B){var _112crap = \"s\"; return \"\" + B + \"\";};function d(L){var _112crap = \"s\"; return \"\" + L + " ascii
    $s18 = "x66\";function O(OmE){var _112crap = \"s\"; return \"\" + OmE + \"\";};function VA(y){var _112crap = \"s\"; return \"\" + y + \"" ascii
    $s19 = "pi, lk);var Viv = \"J\";Viv = SN(dh, ypi);return SN(p, Viv);}var KA = false,v0 = false;for (var t = Lar; t < PHO() * 1; t++){if " ascii
    $s20 = "7\\x65tU\";function i(OOz){var _112crap = \"s\"; return \"\" + OOz + \"\";};function VT(LLE){var _112crap = \"s\"; return \"\" +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}