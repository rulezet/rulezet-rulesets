rule sig_20160323_50e150082abd1892956c3535a5e30fbf {
  meta:
    description = "datamaliciousorder - file 20160323_50e150082abd1892956c3535a5e30fbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97afde598a58e9dca6f26b3c7eeec41dff5bf9ca36b209b397686811246c4acf"

  strings:
    $s1  = "function rY(HTv){var _112crap = \"s\"; return \"\" + HTv + \"\";};var H1 = \"\\x73\\x65\",vBM = \"clo\";function z0(a5){var _112" ascii
    $s2  = "\"+\"\\x68\"+\"arAt\"](5);var cE = \"is\\x65c\",UMW = \"C\\x4dil\\x6c\";var pK = \"getUT\";function B(V0){var _112crap = \"s\"; " ascii
    $s3  = " + mBf + \"\";};function gS(CeV){var _112crap = \"s\"; return \"\" + CeV + \"\";};var E0 = \".exe\",h = \"\\x59Q\\x68Ju\";var r1" ascii
    $s4  = "74e\\x4f\",Szj = S[\"c\"+\"\\x68\"+\"arAt\"](2);var w = sYR[\"c\"+\"\\x68\"+\"arAt\"](4),Bqi = false;var AAv = function JG() {re" ascii
    $s5  = "z, true);};}function l(gR) {var yw = (1, 2, 3, 4, 5, gR); return yw;};MvR = (k) ? 14134 : 414234;DD = WScript[M()](U4 + CsU(Rtw)" ascii
    $s6  = " 0,DY = 0;function OE(){var Gy = new this[B(au) + TDH(Wr)](),bTv = Gy[W(pK) + Z(UMW) + wYy(cE) + a0(r) + y + uPQ(njE)]();WScript" ascii
    $s7  = "[b1(j1) + DF(U)](nS());var Gy = new this[au + Wr](),ObQ = Gy[Bz(pK) + UMW + IaV(cE) + xvH(r) + wvH(y) + V1(njE)]();WScript[j1 + " ascii
    $s8  = "t(); Y0 = WScript[zmp(w) + Szj + xOO(N) + yIJ(WQ) + T0(FEX)](Hvq); var j = true; while (j){try {Y0[Os(hOI) + E1](ZW(SdS), A(a3) " ascii
    $s9  = "rAt\"](3);var j1 = \"Slee\";function W(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};function Z(b0){var _112crap = \"s\"; " ascii
    $s10 = " = \"TC\";var hP = \"getU\",YH = \"e\";var fOi = \"Da\\x74\";function b1(dAl){var _112crap = \"s\"; return \"\" + dAl + \"\";};f" ascii
    $s11 = "H + \"\";};var AUn = \"FCSsFo\",BL = \"\\x64\";var CP = \"\\x6e\",k3 = \"e\";var VL = AUn[\"c\"+\"\\x68\"+\"arAt\"](3);function " ascii
    $s12 = "= \"SV5hir\",N0 = \"\\x4cHTTP\";var d = \"X\\x4d\",FF = \"XML2\\x2e\";var SyI = xkJ[\"c\"+\"\\x68\"+\"arAt\"](0),J = \"M\";funct" ascii
    $s13 = "vqt(){return vL(J) + Asx(SyI) + rXM(FF) + vgX(d) + L(N0);};function ywf(lG, H){return lG - H;};function M(){return AKz(w) + Szj " ascii
    $s14 = "c){var _112crap = \"s\"; return \"\" + Zc + \"\";};var D0 = \"ate\",VKD = \"st\";var g0 = \"ready\";function U3(x0){var _112crap" ascii
    $s15 = "function vp() {return ((k == gW) && (k == true)) ? true : false;};if (k && vp() && gW){function pM() {return AAv[s(aZh) + On(LxQ" ascii
    $s16 = "\\x6d\";var iI = \"\\x74r\\x65\",g1 = \"S\";var wZ = \"B.\",oMt = \"OD\";var Rtw = \"D\",U4 = p3[\"c\"+\"\\x68\"+\"arAt\"](0);fu" ascii
    $s17 = "r(VKD) + UJ(D0)] < 4 ) {WScript[r0(j1) + J1(U)](nS() * 10)};j = false;} catch(qy){j = (kLA(lJ) + u(Q2), LJS(G) + QUy, X(K0) + OC" ascii
    $s18 = "= \"\\x61\\x4f\\x69\";var Be = \"\\x303A\",cHA = \"Z%u\";var fiw = \"\\x2f\",Y2 = cHA[\"c\"+\"\\x68\"+\"arAt\"](1);var vLu = \"%" ascii
    $s19 = "L0 = Z1[\"c\"+\"\\x68\"+\"arAt\"](5),uxR = \"t\";var o0 = \"n\",caH = \"ope\";function CsU(ki){var _112crap = \"s\"; return \"\"" ascii
    $s20 = "fK = O[\"c\"+\"\\x68\"+\"arAt\"](0),b2 = \"\\x343\";var qB = \"ato\\x72\",oxH = \"ac\\x75\";var f = \"://ev\",a3 = \"\\x68ttp\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}