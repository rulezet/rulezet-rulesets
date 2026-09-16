rule sig_20160323_ea492006a4bb6e2bbb4dbedbfd31f574 {
  meta:
    description = "datamaliciousorder - file 20160323_ea492006a4bb6e2bbb4dbedbfd31f574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c36078c944cab69e382a5070ad9263395d8e06ea34cf994e3e1482e7542e8f3"

  strings:
    $s1  = "* RRa + per; break;}}function yTv() {return ((ndq == uj) && (ndq == true)) ? true : false;};if (ndq && yTv() && uj){function s()" ascii
    $s2  = "= b[TYT(Gly) + v0(mC) + yaw + hC + JV(ai)]();WScript[yOp(u0)](oC());var b = new this[ze(dz)](),O = b[U0(Gly) + w1(mC) + Qxk(yaw)" ascii
    $s3  = "function iOR(cGa){var _112crap = \"s\"; return \"\" + cGa + \"\";};var I2 = \"\\x73\\x65\",HvV = \"clo\";function Dj(iB){var _11" ascii
    $s4  = " + rbN(hC) + dU(ai)]();WScript[Pje(u0)](oC());var b = new this[Hd(dz)](),c = b[O0(Gly) + H(mC) + yaw + BR(hC) + a(ai)]();var RRa" ascii
    $s5  = "D) + L0 + UsA(i0);}; mBg = g(); xx = WScript[On + w + D(UvL) + hV(KPr) + I(JN)](mBg); var U = true; while (U){try {xx[r0(WC) + O" ascii
    $s6  = "};function iV(NW, qd){return NW - qd;};function cvo(){return y0(On) + P0(w) + UvL + Am(KPr) + ur(JN);};/*@cc_on  @if (@_win32 ||" ascii
    $s7  = "_112crap = \"s\"; return \"\" + izB + \"\";};var Jh = \"idfDr5UN0\",bw = \"nk\";var C0 = \"a\",K = \"k3os\\x30\";var DY = \"com/" ascii
    $s8  = "\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](3);var Dm0 = \"read\";function XM(ZM){var _112crap = \"s\"; return \"\" + ZM + \"\";};var ty " ascii
    $s9  = "ld(Dm0) + N1(pj) + ucy(W0) + tts(tc)] < 4 ) {WScript[t(u0)](oC() * 10)};U = false;} catch(mzF){U = (x2(N2) + I0(XJJ), nIs(n) + W" ascii
    $s10 = "t\\x65\",w = \"ea\";var On = \"Cr\",XT = false;var NX = function u() {return WScript[JwF(On) + F0(w) + ZCA(UvL) + RcG(KPr) + JN]" ascii
    $s11 = "Y + \"\";};function TqP(Ld){var _112crap = \"s\"; return \"\" + Ld + \"\";};var l = \"AJcrlgMp\",D0 = \"Shell\";var x0 = \"\\x69" ascii
    $s12 = "c) + J(W) + q(ed) + ss(x0) + TqP(D0));}();function y(x){NX[mF](x, 0, 0);};function g(){return jAM + Gls + TX + inZ + CM + e(BS);" ascii
    $s13 = " return \"\" + iB + \"\";};var DL = \"PjcwlSxIsRI\",B = \"\\x46ile\";var G1 = \"aveTo\",cvx = DL[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+" ascii
    $s14 = "(cUo){var _112crap = \"s\"; return \"\" + cUo + \"\";};function Am(khR){var _112crap = \"s\"; return \"\" + khR + \"\";};functio" ascii
    $s15 = "ts(k){var _112crap = \"s\"; return \"\" + k + \"\";};var isj = \"UCjyS738a\",tc = \"at\\x65\";var W0 = \"st\",pj = isj[\"c\"+\"" ascii
    $s16 = ";function Sm(xe){var _112crap = \"s\"; return \"\" + xe + \"\";};function V(c6){var _112crap = \"s\"; return \"\" + c6 + \"\";};" ascii
    $s17 = "x41\"+\"t\"](4),yvP = \":\\x2f\\x2fk\\x61\";var kF = \"h\\x74tp\";function OlR(Vi){var _112crap = \"s\"; return \"\" + Vi + \"\"" ascii
    $s18 = "61\"+\"\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](4),EX = \"eat\\x65\";var g0 = \"Cr\";function e(vKZ){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + tpQ + \"\";};function D(kMa){var _112crap = \"s\"; return \"\" + kMa + \"\";};function hV(v){v" ascii
    $s20 = "1){var _112crap = \"s\"; return \"\" + a1 + \"\";};var hl = \"2USjGWmml\",dN = \"ET\";var be = hl[\"c\"+\"\\x68\"+\"\"+\"\\x61\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}