rule sig_20160323_b0d7229838b087414db2abebb63e6230 {
  meta:
    description = "datamaliciousorder - file 20160323_b0d7229838b087414db2abebb63e6230.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95f33aef407db6626fa24bfbf42af13fa69e0e681221bebdce8e0f8fae4c5d4e"

  strings:
    $s1  = "function w1(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};function iNu(cH){var _112crap = \"s\"; return \"\" + cH + \"\";}" ascii
    $s2  = "mz){var _112crap = \"s\"; return \"\" + mz + \"\";};var Bz = \"%\\x2f\",ci = \"TEMP\";var o0 = \"\\x25\";function bN(n1){var _11" ascii
    $s3  = "ction BC(){var e = new this[Lu(FdS)](),W = e[gIv(qDa) + m + Ij(R) + N(d0) + y1(md) + t3(G)]();WScript[G0(hwx)](s());var e = new " ascii
    $s4  = "this[Unh(FdS)](),Km = e[eBl(qDa) + U(m) + R + JMw(d0) + yT(md) + U0(G)]();WScript[tP(hwx)](s());var e = new this[SZe(FdS)](),co " ascii
    $s5  = "4f\",Rz = a[\"c\"+\"\\x68\"+\"arAt\"](5);var Lb = \"C\\x72ea\";function sQH(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};" ascii
    $s6  = "\"+\"arAt\"](0);function t2(gBX){var _112crap = \"s\"; return \"\" + gBX + \"\";};var t1 = \"\\x52u\\x6e\";function gm(Ri){var _" ascii
    $s7  = "M = \"ht\\x74p\";function Ob(Wm){var _112crap = \"s\"; return \"\" + Wm + \"\";};var Vy = \"KTbIdSX\",CFm = Vy[\"c\"+\"\\x68\"+" ascii
    $s8  = "{var _112crap = \"s\"; return \"\" + f0 + \"\";};var LI = \"4lReEn5kxZ\",sH = \"d\";var M2 = LI[\"c\"+\"\\x68\"+\"arAt\"](5),pq " ascii
    $s9  = "\"s\"; return \"\" + gfT + \"\";};var mC = \"KZyVeKH\",LO = mC[\"c\"+\"\\x68\"+\"arAt\"](4);var fz = \"t\",L1 = \"ysta\";var jm " ascii
    $s10 = "urn \"\" + Egn + \"\";};var XoO = \"9Hi4Wa\",Tw = \"\\x66\\x64af\\x61\";var jK = XoO[\"c\"+\"\\x68\"+\"arAt\"](5);function TUO(a" ascii
    $s11 = "F(O3){var _112crap = \"s\"; return \"\" + O3 + \"\";};var wcx = \"V0y4FcF81o0\",RU = \"oYlEG8\";var k3 = \"\\x6fse\",N2 = RU[\"c" ascii
    $s12 = "\"](2);var a0 = wcx[\"c\"+\"\\x68\"+\"arAt\"](5);function Fr(er){var _112crap = \"s\"; return \"\" + er + \"\";};function ld(uLF" ascii
    $s13 = " = \"C\\x4dil\\x6c\";var R = \"U\\x54\",m = Z0[\"c\"+\"\\x68\"+\"arAt\"](4);var qDa = \"ge\";function Lu(uB){var _112crap = \"s" ascii
    $s14 = "\"\";};function qVq(P){var _112crap = \"s\"; return \"\" + P + \"\";};var vu = \"naryrRS\",Jdn = vu[\"c\"+\"\\x68\"+\"arAt\"](1)" ascii
    $s15 = "{return sQH(zdf) + fzy(F) + o(Uye) + sc(AS) + T;};function c(O, lzq){return O - lzq;};function Cx(){return n0(SIT) + V(wp) + Tq(" ascii
    $s16 = "& ERn() && EI){function J() {return ODL[M0 + bN(kj) + DL(SM) + FzQ(U2) + i0(XAv) + x0(FOx) + GCd(hJq) + znQ(xWI) + OLF(v)](Q1(o0" ascii
    $s17 = "ue; M = \"07t9gasdf76ags\" + 123313 * x + M; break;}}function ERn() {return ((W0 == EI) && (W0 == true)) ? true : false;};if (W0" ascii
    $s18 = "(fz) + k2(LO)] < 4 ) {WScript[c0(hwx)](s() * 10)};RV = false;} catch(t){RV = (D0(OXo) + q(bc) + qVq(Jdn), TUO(tk) + YY(vU) + Ip(" ascii
    $s19 = "r y = \"c\\x74\",Yj = \"je\";var l = \"b\",wp = \"\\x65\\x61\\x74eO\";var SIT = \"\\x43r\",iYN = false;var ODL = function YjU() " ascii
    $s20 = " s4 = \"9tmFyKIil\",pVz = s4[\"c\"+\"\\x68\"+\"arAt\"](4);var wMg = \"eBod\",H1 = \"p\\x6f\\x6e\\x73\";var GU = \"Res\";function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}