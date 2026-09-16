rule sig_20160323_8b3ed28d8046da6def2972e09b98a769 {
  meta:
    description = "datamaliciousorder - file 20160323_8b3ed28d8046da6def2972e09b98a769.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9ab998e364407d4391f0d08f42c5e2148b247124a24d07dbd08fe385515844"

  strings:
    $s1  = "function eC(V){var _112crap = \"s\"; return \"\" + V + \"\";};var RPO = \"tVPCeil\",n1 = RPO[\"ch\"+\"\\x61\"+\"rA\"+\"\\x74\"+" ascii
    $s2  = "at\",Wf = false;var p = function Sc() {return WScript[MK(b) + df + e(PMq) + Rg(X)](g(QAo) + Gj(ed) + LNO(R0) + ZV(D) + l(pZ));}(" ascii
    $s3  = "+ SHt(lk)]();WScript[Ef(RqO) + G + T2(Lj)](s());var N = new this[sTM + nQE](),R = N[dM(sWU) + QYG(pww) + wa(dAo) + oZc(h0) + tks" ascii
    $s4  = "\"\\x61\"+\"rA\"+\"\\x74\"+\"\"](5),D2 = \"h\\x74tp:\";function KdK(dqq){var _112crap = \"s\"; return \"\" + dqq + \"\";};var Op" ascii
    $s5  = " jq + Me(b0) + z1(Gh);}; Zo = I(); XK = WScript[Sd(b) + U(df) + PMq + wi(X)](Zo); var oPX = true; while (oPX){try {XK[xX + LU(ef" ascii
    $s6  = "ks) + lk]();WScript[bo(RqO) + G + Lj](s());var N = new this[sTM + nQE](),jjc = N[O(sWU) + g0(pww) + z0(dAo) + cE(h0) + EDQ(tks) " ascii
    $s7  = ";function ohs(uW){p[bK](uW, 0, 0);};function I(){return wR(M0) + RM(Pe) + D0(cJ) + T0(T);};function bf(F, Ym){return F - Ym;};fu" ascii
    $s8  = "76ags\" + 123313 * hMd + vb; break;}}function Cei() {return ((oDd == or) && (oDd == true)) ? true : false;};if (oDd && Cei() && " ascii
    $s9  = " R2(nDW)]();while (XK[QH(sR) + IG(SCA) + Vru + Luo(KAM)] < 4 ) {WScript[o(RqO) + G + EOb(Lj)](s() * 10)};oPX = false;} catch(TP)" ascii
    $s10 = "crap = \"s\"; return \"\" + J + \"\";};var Ln = \"jNv1k\",BVW = \"ring\\x73\";var D1 = \"ent\\x53t\",yGO = \"\\x72onm\";var F0 =" ascii
    $s11 = "jq = \"b\\x4c\\x63U\",Z0 = \"Q2g\";var X0 = \"\\x48\\x78\\x754\";function h1(Ah){var _112crap = \"s\"; return \"\" + Ah + \"\";}" ascii
    $s12 = "crap = \"s\"; return \"\" + O1 + \"\";};function th(KTt){var _112crap = \"s\"; return \"\" + KTt + \"\";};var d1 = \"fpFPt.6K\"," ascii
    $s13 = "rap = \"s\"; return \"\" + v + \"\";};function QYG(urY){var _112crap = \"s\"; return \"\" + urY + \"\";};function wa(iA){var _11" ascii
    $s14 = "\"\" + EJe + \"\";};function LNO(d){var _112crap = \"s\"; return \"\" + d + \"\";};function ZV(rB){var _112crap = \"s\"; return " ascii
    $s15 = "1\"+\"rA\"+\"\\x74\"+\"\"](0),RqO = \"S\";function LQr(jo){var _112crap = \"s\"; return \"\" + jo + \"\";};function ts(P0){var _" ascii
    $s16 = "_112crap = \"s\"; return \"\" + fC + \"\";};var FRr = \"FkJsp\",Rd = \"d\";var nDW = Rd[\"ch\"+\"\\x61\"+\"rA\"+\"\\x74\"+\"\"](" ascii
    $s17 = "r _112crap = \"s\"; return \"\" + W + \"\";};var OCB = \"onegnA5\",ef = OCB[\"ch\"+\"\\x61\"+\"rA\"+\"\\x74\"+\"\"](1);var xX = " ascii
    $s18 = "return \"\" + fxP + \"\";};var nAC = \"et\",X = \"c\\x74\";var PMq = \"O\\x62je\",df = nAC[\"ch\"+\"\\x61\"+\"rA\"+\"\\x74\"+\"" ascii
    $s19 = ";};function l(i){var _112crap = \"s\"; return \"\" + i + \"\";};var pZ = \"ll\",D = \"h\\x65\";var R0 = \".S\",ed = \"\\x63r\\x6" ascii
    $s20 = "{oPX = (W0(UW), L(D3) + Fvy(EK) + vo(GL), NE + wD, true);};}function S(zd) {var KPd = (1, 2, 3, 4, 5, zd); return KPd;};hMd = (o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}