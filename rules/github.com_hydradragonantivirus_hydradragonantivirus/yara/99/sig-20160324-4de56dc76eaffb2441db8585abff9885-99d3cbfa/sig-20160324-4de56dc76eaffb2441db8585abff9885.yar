rule sig_20160324_4de56dc76eaffb2441db8585abff9885 {
  meta:
    description = "datamaliciousorder - file 20160324_4de56dc76eaffb2441db8585abff9885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34101a28b894b96a0e8b2bed097ade2d847b13ae17080432b6c4e1ab6a9eb878"

  strings:
    $s1  = "function XnO(KT){var _112crap = \"s\"; return \"\" + KT + \"\";};var nyV = \"close\";function HpP(M1){var _112crap = \"s\"; retu" ascii
    $s2  = "var h = \"te\\x4fb\",sU = \"Crea\";var Pb = false,ORk = function K() {return WScript[yi(sU) + d(h) + yap(u) + Z(N)](Z0 + AXg(mMK" ascii
    $s3  = "= gUb[zCg(mk) + wh(Kc) + ogM(UTf) + Wrm + tI(C) + wk(n) + wXx(XMV)]();WScript[PE(ZC) + jY(X0)](j());var gUb = new this[f0(g)]()," ascii
    $s4  = "w = (1, 2, 3, 4, 5, qZ); return Pw;};j0 = (vp) ? 14134 : 414234;Y = WScript[T()](vvJ(DSP) + HO + KEh(Va) + lQ(tb));cdO = Y;q = (" ascii
    $s5  = "(x) + C0(l2) + V2(Qn), false);J[T0(N1) + iR(Le) + DR(NVP)]();while (J[T1 + lq(ZGb) + Ken(fR)] < 4 ) {WScript[Mw(ZC) + CV(X0)](j(" ascii
    $s6  = "gUb[mk + bzq(Kc) + xiA(UTf) + CO(Wrm) + Ke(C) + CZw(n) + XMV]();WScript[Qoh(ZC) + nDL(X0)](j());var gUb = new this[mUx(g)](),UU " ascii
    $s7  = " V2(ilf){var _112crap = \"s\"; return \"\" + ilf + \"\";};var CQ = \"WAh8fF\",NZ = \"ceec\";var Qn = \"js\",l2 = NZ[\"\"+\"\\x63" ascii
    $s8  = "\";var V = \"te\",EoX = a[\"\"+\"\\x63\"+\"harAt\"](4);var l = \"\\x44\";function Qoh(FhS){var _112crap = \"s\"; return \"\" + F" ascii
    $s9  = "od\";var tB = \"\\x6fns\",wTs = \"\\x65s\\x70\";var D1 = VzS[\"\"+\"\\x63\"+\"harAt\"](0);function hSg(L0){var _112crap = \"s\";" ascii
    $s10 = "\",Kc = \"etUTC\";var mk = NN[\"\"+\"\\x63\"+\"harAt\"](2);function rQy(dlz){var _112crap = \"s\"; return \"\" + dlz + \"\";};fu" ascii
    $s11 = "\"s\"; return \"\" + JtQ + \"\";};var gJ = \"ytSBz1p\",X0 = \"l\\x65e\\x70\";var ZC = gJ[\"\"+\"\\x63\"+\"harAt\"](2);function b" ascii
    $s12 = "x66da\\x66a\";var CQT = xFd[\"\"+\"\\x63\"+\"harAt\"](2);function XAI(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};var bt" ascii
    $s13 = ";function D2(H){var _112crap = \"s\"; return \"\" + H + \"\";};var VzS = \"Rqax\",qn = \"yFEJ\";var c1 = qn[\"\"+\"\\x63\"+\"har" ascii
    $s14 = "mm(vk);};function OXP(Ou, r){return Ou - r;};function T(){return FUr(sU) + r0(h) + aKh(u) + KZY(N);};/*@cc_on  @if (@_win32 || @" ascii
    $s15 = " true : false;};if (vp && Wb() && Fcu){function puN() {return ORk[a0(Ktq) + Yt + c(IE) + E1 + CK + l0(UG) + MMT(pd) + b1(Rf)](f2" ascii
    $s16 = "3313 * j0 + q; Fcu = true; q = \"07t9gasdf76ags\" + 123313 * j0 + q; break;}}function Wb() {return ((vp == Fcu) && (vp == true))" ascii
    $s17 = "+ \"\";};function Ken(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};var fR = \"a\\x74e\",ZGb = \"\\x73\\x74\";var T1 = \"r" ascii
    $s18 = "\\x50%\";var f2 = \"\\x25TE\";function a0(a1){var _112crap = \"s\"; return \"\" + a1 + \"\";};function c(thj){var _112crap = \"s" ascii
    $s19 = "RxX = \"exe\";var m0 = \"1Jay.\",aj = Ei[\"\"+\"\\x63\"+\"harAt\"](2);var YmC = \"iAG\",G = \"\\x6f\\x61\";var PSQ = \"D\\x33ss" ascii
    $s20 = "\";var tr = CDq[\"\"+\"\\x63\"+\"harAt\"](0),ae = uxE[\"\"+\"\\x63\"+\"harAt\"](1);var mMK = \"Scri\",Z0 = \"W\";function yi(nC)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}