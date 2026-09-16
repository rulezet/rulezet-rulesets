rule sig_20160323_3db88238553e65d53c6ab7bb8f9f648a {
  meta:
    description = "datamaliciousorder - file 20160323_3db88238553e65d53c6ab7bb8f9f648a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46b47657cca80a6d2ccc4a322b881f45285f888b0cdf83270b0c2041519bb5bb"

  strings:
    $s1  = "function LKa(ojR){var _112crap = \"s\"; return \"\" + ojR + \"\";};function yt(i0){var _112crap = \"s\"; return \"\" + i0 + \"\"" ascii
    $s2  = "(Ms) + sbb(lO) + e0(E) + K0 + TVa(z) + nRe + Ql + Fq(pI) + NI(Y)]();WScript[DT(DJe) + me(e1)](GuL());var Fg = new this[D1(f) + M" ascii
    $s3  = "xIv), false);W[bbW(W2) + J4(Sim) + I2(yGL)]();while (W[PC + Ptl(Q3) + Bkm(Se)] < 4 ) {WScript[uAg(DJe) + I1(e1)](GuL() * 10)};K " ascii
    $s4  = "3\"+\"harA\"+\"\\x74\"+\"\"](0);var s2 = \"//\\x65va\",Pv = \"h\\x74tp:\";function V1(p1){var _112crap = \"s\"; return \"\" + p1" ascii
    $s5  = "XAe(xTF)](oC, 0, 0);};function GO(){return H(u) + dEv(q0) + cx(I) + fIX(yRB) + v(TuS);};function X(bg, jd){return bg - jd;};func" ascii
    $s6  = " G = \"teO\",X0 = \"ea\";var HhK = j[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"](2),bL = \"C\";var h = false,C0 = function e() {retu" ascii
    $s7  = "3, 4, 5, C); return aT;};UZ = (wri) ? 14134 : 414234;nS = WScript[pUf()](uyi(kn) + a1(x) + vx + nTw(v1) + zM(I3) + lcA(r0) + ZQ(" ascii
    $s8  = "\\x2f\";var f0 = gE[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"](0),y0 = \"\\x25T\\x45\";function gd(pz){var _112crap = \"s\"; return" ascii
    $s9  = "F){var _112crap = \"s\"; return \"\" + KZF + \"\";};function bQ(GUy){var _112crap = \"s\"; return \"\" + GUy + \"\";};function X" ascii
    $s10 = "s\"; return \"\" + Q4 + \"\";};function nTw(O2){var _112crap = \"s\"; return \"\" + O2 + \"\";};function zM(Tu){var _112crap = " ascii
    $s11 = "tion mbc(Ky){var _112crap = \"s\"; return \"\" + Ky + \"\";};function X1(tso){var _112crap = \"s\"; return \"\" + tso + \"\";};f" ascii
    $s12 = "{var _112crap = \"s\"; return \"\" + if0 + \"\";};function Ja(RT){var _112crap = \"s\"; return \"\" + RT + \"\";};function D1(HH" ascii
    $s13 = " \"\" + pAF + \"\";};function dEv(FT){var _112crap = \"s\"; return \"\" + FT + \"\";};function cx(Kt){var _112crap = \"s\"; retu" ascii
    $s14 = " return \"\" + F + \"\";};function KU(C1){var _112crap = \"s\"; return \"\" + C1 + \"\";};function nB(M){var _112crap = \"s\"; r" ascii
    $s15 = " + \"\";};function D0(ZW){var _112crap = \"s\"; return \"\" + ZW + \"\";};function XXk(hnB){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = "ction E0(ivc){var _112crap = \"s\"; return \"\" + ivc + \"\";};function iky(Pus){var _112crap = \"s\"; return \"\" + Pus + \"\";" ascii
    $s17 = "\"; return \"\" + NAP + \"\";};function Ko(KuG){var _112crap = \"s\"; return \"\" + KuG + \"\";};function zPH(MRR){var _112crap " ascii
    $s18 = "function LKa(ojR){var _112crap = \"s\"; return \"\" + ojR + \"\";};function yt(i0){var _112crap = \"s\"; return \"\" + i0 + \"\"" ascii
    $s19 = "\"tUTC\\x4d\";var xjF = \"ge\",iJL = \"Date\";function DT(Ai){var _112crap = \"s\"; return \"\" + Ai + \"\";};function me(TI){va" ascii
    $s20 = "cg){var _112crap = \"s\"; return \"\" + Ocg + \"\";};function P1(cbC){var _112crap = \"s\"; return \"\" + cbC + \"\";};var gE = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}