rule sig_20160324_7a28a1f0ed4699e3de3ddb21cf60b6fa {
  meta:
    description = "datamaliciousorder - file 20160324_7a28a1f0ed4699e3de3ddb21cf60b6fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68224c749def79cd2b8ece7773cdcdcd16a5ac54b6d991e1949211d4da30d9af"

  strings:
    $x1  = "var sQ = \"\\x63lo\\x73e\";function lTd(y1){var _112crap = \"s\"; return \"\" + y1 + \"\";};var ep = \"\\x65\",LZl = \"oF\\x69l" ascii
    $s2  = "{return WScript[DR](XU + I + i);}();var bb = 123213,YTU = \"MSXML2.XMLHTTP\";var l = 2123213,hj = 0;function H(MZ){rE[os(b)](MZ," ascii
    $s3  = ") + P, U + Zc, 2);};}function BYB(GeO) {var PJ = (1, 2, 3, 4, 5, GeO); return PJ;};FA = WScript[J0()](FoC + CEP(MU) + mfn(F0));E" ascii
    $s4  = "Ub(eWI) + w + E1]();WScript[AD + gdF](bmp());var E = new this[DD](),oe = E[Cw(tX) + iKb(eWI) + w + TW(E1)]();WScript[AD + v(gdF)" ascii
    $s5  = "L(vyc) + grj;}; E0 = bkS(); H0 = WScript[DR](E0); var F = 1; while (F){try {H0[Z0](t, Ze + mh + M + lQz(qnV) + zEv + b2 + s + E3" ascii
    $s6  = " mh = \"//e\\x6dp\",Ze = \"ht\\x74p:\";var t = \"G\\x45T\";function o(iX){var _112crap = \"s\"; return \"\" + iX + \"\";};var Z0" ascii
    $s7  = "j, hj);};function bkS(){return YTU;};function aQ(ip, j){return ip - j;};function J0(){return DR;};/*@cc_on  @if (@_win32 || @_wi" ascii
    $s8  = "123313 * ZY + FJg; HEl = true; FJg = \"07t9gasdf76ags\" + 123313 * ZY + FJg; break;}}function J() {return ((Fz == true) && (Fz =" ascii
    $s9  = "HEl)) ? 1 : hj;};if (Fz && J() && HEl){function el() {return rE[twS + Qj + e + lC0 + xQ(RjG)](MEG(E2) + DQG) + Vc + su + Qi + YM" ascii
    $s10 = ", false);H0[EGF(Ona)]();Kc = \"Sleep\";while (H0[CWr + a1 + A] < 4 ) {WScript[Kc](bmp() * 10)};F = hj;} catch(wv){F = (Bl, VvN(k" ascii
    $s11 = "\\x47m\\x77\";var Vc = \"\\x4a9kuT\";function MEG(Zi){var _112crap = \"s\"; return \"\" + Zi + \"\";};var DQG = \"P%\\x2f\",E2 =" ascii
    $s12 = "aQ(ZY, FJg);}var Fz = false,HEl = false;for (var V = hj; V < bmp() * 1; V++){if (W() != hj){Fz = true; FJg = \"07t9gasdf76ags\" " ascii
    $s13 = "5n\";function YML(f){var _112crap = \"s\"; return \"\" + f + \"\";};var grj = \"\\x65\",vyc = \"\\x37f.ex\";var Qi = \"g\\x35\\x" ascii
    $s14 = "12crap = \"s\"; return \"\" + L + \"\";};function TW(xd){var _112crap = \"s\"; return \"\" + xd + \"\";};var E1 = \"on\\x64\\x73" ascii
    $s15 = "t\\x55\";var AA = \"\\x44a\\x74e\";function v(r){var _112crap = \"s\"; return \"\" + r + \"\";};var gdF = \"\\x70\",AD = \"Sl\\x" ascii
    $s16 = "\";var eWI = \"\\x43M\\x69\\x6c\",tX = \"\\x67\\x65\\x74UT\";var DD = \"\\x44ate\";function os(b0){var _112crap = \"s\"; return " ascii
    $s17 = "tion xQ(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};var RjG = \"\\x72\\x69ngs\",lC0 = \"e\\x6etSt\";var e = \"\\x69ronm" ascii
    $s18 = "Tvl){var _112crap = \"s\"; return \"\" + Tvl + \"\";};function Cw(Sj){var _112crap = \"s\"; return \"\" + Sj + \"\";};function i" ascii
    $s19 = "var sQ = \"\\x63lo\\x73e\";function lTd(y1){var _112crap = \"s\"; return \"\" + y1 + \"\";};var ep = \"\\x65\",LZl = \"oF\\x69l" ascii
    $s20 = "\"s\"; return \"\" + qWY + \"\";};var VDk = \"\\x65\",O0 = \"\\x77rit\";var x = \"t\\x79\\x70e\",f0 = \"o\\x70\\x65\\x6e\";funct" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}