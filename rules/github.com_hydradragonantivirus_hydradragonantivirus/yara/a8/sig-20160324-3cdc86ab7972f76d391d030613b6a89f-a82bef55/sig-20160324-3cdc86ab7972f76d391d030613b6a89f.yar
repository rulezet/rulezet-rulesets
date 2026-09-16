rule sig_20160324_3cdc86ab7972f76d391d030613b6a89f {
  meta:
    description = "datamaliciousorder - file 20160324_3cdc86ab7972f76d391d030613b6a89f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e43fe0908f03ba6e024d07eb231d4ab3217c859bc6c485fac77c38ed547dfb"

  strings:
    $s1  = "var gK = \"cl\\x6fse\",Gll = \"\\x65\";var UZ = \"o\\x46il\",IDT = \"\\x53ave\\x54\";function H1(Cd){var _112crap = \"s\"; retur" ascii
    $s2  = "A() {return WScript[hqs](xBM + ezH(Jc) + g);}();var D = 123213,PXI = \"MSXML2.XMLHTTP\";var McH = 2123213,WA = 0;function Z(V){D" ascii
    $s3  = " N1, 2);};}function rh(dl) {var al = (1, 2, 3, 4, 5, dl); return al;};PtI = WScript[rE()](T + p + W1);mu = PtI;mu[(m)]();mu[h0(Q" ascii
    $s4  = "+ sbA(l) + SkW(KTc) + nb;}; mu = v(); e = WScript[hqs](mu); var Q = 1; while (Q){try {e[m](KJs, w0(fwB) + Nd + qSr + vS + X + ZY" ascii
    $s5  = "Cf = B[bb + d + Dh(erQ) + W + OMa]();WScript[O](zXP());var B = new this[fw](),mp = B[bb + d + erQ + W + OMa]();WScript[KFR(O)](z" ascii
    $s6  = "yg(V0)](V, WA, WA);};function v(){return PXI;};function c(ysA, i){return ysA - i;};function rE(){return hqs;};/*@cc_on  @if (@_w" ascii
    $s7  = "= ahU)) ? 1 : WA;};if (fZf && uKC() && ahU){function ag() {return D0[WZ + Wjd(D1) + N0(jWt) + tj + kWD + RT](zlb + iW) + F(NRr) " ascii
    $s8  = "gs\" + 123313 * C + s; ahU = true; s = \"07t9gasdf76ags\" + 123313 * C + s; break;}}function uKC() {return ((fZf == true) && (fZ" ascii
    $s9  = "\";function h0(D2){var _112crap = \"s\"; return \"\" + D2 + \"\";};var QZ = \"\\x74ype\",fe = \"ope\\x6e\";var W1 = \"\\x65am\"," ascii
    $s10 = "L, false);e[jO]();aS = \"Sleep\";while (e[Mn + ez + Lrp] < 4 ) {WScript[aS](zXP() * 10)};Q = WA;} catch(VY){Q = (s0, e0 + Hv, pG" ascii
    $s11 = "4c2\\x2eX\";var lqR = \"\\x4dSX\\x4d\";function ezH(n){var _112crap = \"s\"; return \"\" + n + \"\";};var g = \"h\\x65ll\",Jc = " ascii
    $s12 = " _112crap = \"s\"; return \"\" + Hc + \"\";};var OMa = \"\\x73\",W = \"\\x63ond\";var erQ = \"\\x6clise\",d = \"\\x54CMi\";var b" ascii
    $s13 = " \"Dat\\x65\";function yg(Ey){var _112crap = \"s\"; return \"\" + Ey + \"\";};var V0 = \"\\x52un\",bk = \"\\x54P\";var H0 = \"ML" ascii
    $s14 = "n Dh(pb){var _112crap = \"s\"; return \"\" + pb + \"\";};function f(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function" ascii
    $s15 = "\"; return \"\" + mm + \"\";};function SkW(ms){var _112crap = \"s\"; return \"\" + ms + \"\";};var nb = \"\\x2eexe\",KTc = \"t" ascii
    $s16 = "var gK = \"cl\\x6fse\",Gll = \"\\x65\";var UZ = \"o\\x46il\",IDT = \"\\x53ave\\x54\";function H1(Cd){var _112crap = \"s\"; retur" ascii
    $s17 = "9\",Ui = \"ge\\x74\\x55\";var ej = \"\\x44ate\";function KFR(pZ){var _112crap = \"s\"; return \"\" + pZ + \"\";};var O = \"Sle" ascii
    $s18 = "rn c(C, s);}var fZf = false,ahU = false;for (var csB = WA; csB < zXP() * 1; csB++){if (cd() != WA){fZf = true; s = \"07t9gasdf76" ascii
    $s19 = "nction N0(cS){var _112crap = \"s\"; return \"\" + cS + \"\";};var RT = \"\\x73\",kWD = \"\\x74r\\x69ng\";var tj = \"\\x65ntS\",j" ascii
    $s20 = "XP());var B = new this[fw](),K = B[f(bb) + d + xZo(erQ) + W + OMa]();var C = \"ofZ\";C = c(mp, JCf);var s = \"fm\";s = c(K, mp);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}