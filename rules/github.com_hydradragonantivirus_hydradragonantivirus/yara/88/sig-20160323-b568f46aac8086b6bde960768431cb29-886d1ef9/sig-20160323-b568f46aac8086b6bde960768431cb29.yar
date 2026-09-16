rule sig_20160323_b568f46aac8086b6bde960768431cb29 {
  meta:
    description = "datamaliciousorder - file 20160323_b568f46aac8086b6bde960768431cb29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5510d280dc3b12fc794a08e599bbd783428e89c647427d2c224ddfd7f1359cb6"

  strings:
    $s1  = "function WGl(hrx){var _112crap = \"s\"; return \"\" + hrx + \"\";};function lnx(dEu){var _112crap = \"s\"; return \"\" + dEu + " ascii
    $s2  = ";var m2 = \"\\x65c\\x74\",ue = \"teObj\";var m1 = \"C\\x72ea\",lz = false;var lqm = function j0() {return WScript[Ar(m1) + T0(ue" ascii
    $s3  = "cTJ) + Q + a(z) + B0(aN) + NT(KyY)]();WScript[yPj(VwM) + Jc(m3) + f(Tu) + F0(v0) + KVc(gLj)](B());var Y = new this[LQv(e0) + Tjl" ascii
    $s4  = "Y[cTJ + zu(Q) + S(z) + aN + UV(KyY)]();WScript[Er(VwM) + m3 + Tu + K(v0) + gLj](B());var Y = new this[e0 + YFi(w0)](),vz = Y[wI(" ascii
    $s5  = "4, 5, T); return IR;};WR = (R) ? 14134 : 414234;cY = WScript[m()](L0 + LqJ + fxj(U1) + tA(WIM) + DJ(T2) + BS(gw));E = cY;Irp = (" ascii
    $s6  = "(p2) + rU + br(PO), false);dX[iB(Nr)]();while (dX[iP + bt0 + RSF] < 4 ) {WScript[FL(VwM) + g(m3) + LdR(Tu) + v0 + rQb(gLj)](B() " ascii
    $s7  = "\\x70\",cBB = aoG[\"\"+\"\\x63\"+\"harAt\"](1);var XN = \"ht\";function zR(JRh){var _112crap = \"s\"; return \"\" + JRh + \"\";}" ascii
    $s8  = "rap = \"s\"; return \"\" + tL + \"\";};var EYP = \"IxELglr\",cz = \"eI\";var gLj = \"p\",v0 = cz[\"\"+\"\\x63\"+\"harAt\"](0);va" ascii
    $s9  = "EYP[\"\"+\"\\x63\"+\"harAt\"](5);var VwM = \"S\";function zu(Ye){var _112crap = \"s\"; return \"\" + Ye + \"\";};function S(CZq)" ascii
    $s10 = "3\"+\"harAt\"](3);var Fh = \"K\",Kn = NA[\"\"+\"\\x63\"+\"harAt\"](2);function gu(u){var _112crap = \"s\"; return \"\" + u + \"" ascii
    $s11 = "DO = \"s\";var B3 = ee[\"\"+\"\\x63\"+\"harAt\"](5),Oj = \"\\x52espo\";function ImJ(k){var _112crap = \"s\"; return \"\" + k + " ascii
    $s12 = " tV(aY);};function hE(Xbk, ed){return Xbk - ed;};function m(){return r1(m1) + ly(ue) + M(m2);};/*@cc_on  @if (@_win32 || @_win64" ascii
    $s13 = "3t\",iP = \"ready\";function iB(N1){var _112crap = \"s\"; return \"\" + N1 + \"\";};var Nr = \"se\\x6ed\";function qoO(GQO){var " ascii
    $s14 = "+ 123313 * WR + Irp; P = true; Irp = \"07t9gasdf76ags\" + 123313 * WR + Irp; break;}}function j() {return ((R == P) && (R == tru" ascii
    $s15 = ") ? true : false;};if (R && j() && P){function c() {return lqm[HZS(p1) + VUS(qE) + bOx(r2) + NB(xHy) + V(R0) + QN(xpn) + LRj(i0)" ascii
    $s16 = "\\x44a\";var tY = \"mttx\",h0 = tY[\"\"+\"\\x63\"+\"harAt\"](2);var ST = \"ec\",M0 = \"\\x65\\x4fb\\x6a\";var joJ = \"Crea\\x74" ascii
    $s17 = "rAt\"](1);var T2 = \"a\",WIM = \"re\";var U1 = \"t\",LqJ = \"\\x2eS\";var L0 = \"\\x41\\x44\\x4fDB\";function z0(p3){var _112cra" ascii
    $s18 = ",DT = sn[\"\"+\"\\x63\"+\"harAt\"](0);var B2 = \"o\\x70\\x65\",ky = \"bject\";var GkB = \"eO\",tmW = \"\\x74\";var KG = \"\\x43" ascii
    $s19 = "\\x65\";var o = \"p\\x74.\\x53\\x68\",SL = \"cri\";var e = \"WS\";function Ar(ng){var _112crap = \"s\"; return \"\" + ng + \"\";" ascii
    $s20 = "\",Qs = \"io\";var cq = \"\\x70osit\";function StV(Dt){var _112crap = \"s\"; return \"\" + Dt + \"\";};function fH(VLu){var _112" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}