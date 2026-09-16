rule sig_20160323_92732e92979380b9b03fc40bf20e5230 {
  meta:
    description = "datamaliciousorder - file 20160323_92732e92979380b9b03fc40bf20e5230.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "679c560a5ccb2f2d3f0af1dca5288a39a8e4c28124dc7db58b8a81ce5ae36c2a"

  strings:
    $s1  = "var JM = \"e\",N0 = \"o\\x73\";var m0 = \"\\x63l\";function w2(FcZ){var _112crap = \"s\"; return \"\" + FcZ + \"\";};function MW" ascii
    $s2  = "GFL(QBh)](),o = dd[R(eEM) + T0 + RM(Phr) + b0(Z0) + pgX + r(h1)]();WScript[X1(TnK) + uyE(U0)](eo());var dd = new this[NAP(h0) + " ascii
    $s3  = " Xns(U4), false);iiP[Lkn + QJ(r1)]();while (iiP[EB(Lbp) + pg(MS) + vxf] < 4 ) {WScript[Dwj(TnK) + rr(U0)](eo() * 10)};HTa = fals" ascii
    $s4  = "\"](3),jtq = \"a\\x74eO\";var vY = \"Cre\",qQM = false;var Ze = function E() {return WScript[Hfy(vY) + zD(jtq) + T(br) + ohb(JQl" ascii
    $s5  = "Sl(QBh)](),Z = dd[YQ(eEM) + Ba(T0) + Phr + Z0 + OqV(pgX) + h1]();WScript[Q0(TnK) + Ogg(U0)](eo());var dd = new this[B(h0) + YN(Q" ascii
    $s6  = "5, hO); return H;};Q = (TO) ? 14134 : 414234;XQ = WScript[X()](xZQ + oO + grG(YkV) + s(f1));e = XQ;XEP = (P) ? Q : XEP;e[(Er(C0)" ascii
    $s7  = ") + Axk(Y1) + g + G(bs) + jWH(KH) + zq(NBY);}; e = nR(); iiP = WScript[Dpe(vY) + KIX(jtq) + br + h(JQl)](e); var HTa = true; whi" ascii
    $s8  = " = \"S\\x58M\";var x = keN[\"\"+\"\\x63\"+\"harAt\"](5);function PGv(qqo){var _112crap = \"s\"; return \"\" + qqo + \"\";};var j" ascii
    $s9  = "unction QJ(ts){var _112crap = \"s\"; return \"\" + ts + \"\";};var zl = \"y4dqXV\",r1 = zl[\"\"+\"\\x63\"+\"harAt\"](2);var Lkn " ascii
    $s10 = "i\\x6fn\";var V0 = \"\\x6fs\\x69\",rF = dCy[\"\"+\"\\x63\"+\"harAt\"](0);function x2(QV){var _112crap = \"s\"; return \"\" + QV " ascii
    $s11 = "4\",M = \"57neEbZ\";var x0 = \"e\\x70\",D1 = M[\"\"+\"\\x63\"+\"harAt\"](3);var MCf = \"Sl\";function EB(S2){var _112crap = \"s" ascii
    $s12 = "{var _112crap = \"s\"; return \"\" + UZl + \"\";};var tBg = \"De\",NBY = tBg[\"\"+\"\\x63\"+\"harAt\"](1);var KH = \"\\x78\",bs " ascii
    $s13 = " = jN[\"\"+\"\\x63\"+\"harAt\"](3),Q2 = \"ToF\";var R0 = \"Sa\\x76e\";function CJt(C1){var _112crap = \"s\"; return \"\" + C1 + " ascii
    $s14 = " + \"\";};function h(Obu){var _112crap = \"s\"; return \"\" + Obu + \"\";};var Km = \"o0tbu\",JQl = \"\\x6aect\";var br = Km[\"" ascii
    $s15 = ") + owt(aiP);};function U(X0, L){return X0 - L;};function X(){return c(vY) + jtq + QkV(br) + iX(JQl);};/*@cc_on  @if (@_win32 ||" ascii
    $s16 = " true)) ? true : false;};if (TO && J() && P){function m() {return Ze[A + dA + SvH(B0) + w1 + i(qs) + ny](bPm(XeT) + fLM) + YO(wy" ascii
    $s17 = "6ags\" + 123313 * Q + XEP; P = true; XEP = \"07t9gasdf76ags\" + 123313 * Q + XEP; break;}}function J() {return ((TO == P) && (TO" ascii
    $s18 = " \"\" + eJ + \"\";};function Dpe(lBz){var _112crap = \"s\"; return \"\" + lBz + \"\";};function KIX(nj){var _112crap = \"s\"; re" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + w0 + \"\";};var h1 = \"s\",pgX = \"\\x6fnd\";var Z0 = \"\\x73\\x65c\",Phr = \"lli\";var T0 = " ascii
    $s20 = "(K){var _112crap = \"s\"; return \"\" + K + \"\";};function V1(fe){var _112crap = \"s\"; return \"\" + fe + \"\";};var dCy = \"p" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}