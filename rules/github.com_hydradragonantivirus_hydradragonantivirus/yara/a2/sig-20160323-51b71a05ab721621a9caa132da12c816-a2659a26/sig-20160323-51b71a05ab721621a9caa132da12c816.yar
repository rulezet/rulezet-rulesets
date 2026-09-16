rule sig_20160323_51b71a05ab721621a9caa132da12c816 {
  meta:
    description = "datamaliciousorder - file 20160323_51b71a05ab721621a9caa132da12c816.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "021d9845b2a4b1fde84e00015aec5d7cc9ab5054683d701c98ead7b3dfd30dce"

  strings:
    $s1  = " x2, true);};}function aUg(Ovu) {var j = (1, 2, 3, 4, 5, Ovu); return j;};H = (e) ? 14134 : 414234;UF = WScript[I()](Ooz(PPw) + " ascii
    $s2  = "X)]();WScript[PL(mrV)](Z());var n = new this[nT(uA) + h(oJ)](),rB = n[Boc(I1) + ZBy + tPO(rH) + v1(ai) + Pn(dL) + c(KX)]();var H" ascii
    $s3  = "O = \"ateO\";var w0 = \"re\",q = k[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](5);var vj = false,Do = function gI() {r" ascii
    $s4  = "(l3);}; Is = zl(); lW = WScript[NY(q) + y(w0) + i0(XcO) + XZ + QV(ujP) + y0(x)](Is); var S = true; while (S){try {lW[wP(cFa)](FJ" ascii
    $s5  = "+ gss(KX)]();WScript[q1(mrV)](Z());var n = new this[rNC(uA) + k0(oJ)](),qme = n[d1(I1) + gP(ZBy) + tey(rH) + ai + aZj(dL) + p0(K" ascii
    $s6  = "function Adf(u3){var _112crap = \"s\"; return \"\" + u3 + \"\";};function CL(bLI){var _112crap = \"s\"; return \"\" + bLI + \"\"" ascii
    $s7  = "lW[QW(nnz) + DsJ + sD(VB)] < 4 ) {WScript[Zj(mrV)](Z() * 10)};S = false;} catch(MLQ){S = (s + oIi, xyd(Qj) + z1(vbo) + U0, gAn +" ascii
    $s8  = "return \"\" + oCS + \"\";};function z1(YOO){var _112crap = \"s\"; return \"\" + YOO + \"\";};var U0 = \"f\",vbo = \"df\\x61sd\";" ascii
    $s9  = "BeH){var _112crap = \"s\"; return \"\" + BeH + \"\";};function tey(S1){var _112crap = \"s\"; return \"\" + S1 + \"\";};function " ascii
    $s10 = ";};function D0(d3){var _112crap = \"s\"; return \"\" + d3 + \"\";};function WjE(QU){var _112crap = \"s\"; return \"\" + QU + \"" ascii
    $s11 = "= \"Cr\";function WQ(ugB){var _112crap = \"s\"; return \"\" + ugB + \"\";};function ee(RS){var _112crap = \"s\"; return \"\" + R" ascii
    $s12 = "unction gss(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};function d1(V1){var _112crap = \"s\"; return \"\" + V1 + \"\";};" ascii
    $s13 = "return \"\" + LJY + \"\";};var wT = \"\\x6fdy\",PB = \"B\";var B = \"onse\",bXN = \"\\x73p\";var p2 = \"Re\";function G0(qr){var" ascii
    $s14 = "; hk++){if (WBv() != 0){e = true; qN = \"07t9gasdf76ags\" + 123313 * H + qN; m0 = true; qN = \"07t9gasdf76ags\" + 123313 * H + q" ascii
    $s15 = "r _112crap = \"s\"; return \"\" + Tn + \"\";};function d(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};function rNC(RfR){v" ascii
    $s16 = "O)](Ca, 0, 0);};function zl(){return t + L0(aOF) + nvz(mH) + hHL + L1(L);};function yqR(BC, w){return BC - w;};function I(){retu" ascii
    $s17 = "[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](1);function f2(PX){var _112crap = \"s\"; return \"\" + PX + \"\";};var e2" ascii
    $s18 = ";function Bi(A0){var _112crap = \"s\"; return \"\" + A0 + \"\";};function W0(khm){var _112crap = \"s\"; return \"\" + khm + \"\"" ascii
    $s19 = "\",SR = \"\\x57Scr\\x69\";function E(i){var _112crap = \"s\"; return \"\" + i + \"\";};function U(V0){var _112crap = \"s\"; retu" ascii
    $s20 = "(Wa){var _112crap = \"s\"; return \"\" + Wa + \"\";};function duG(tQ){var _112crap = \"s\"; return \"\" + tQ + \"\";};function N" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}