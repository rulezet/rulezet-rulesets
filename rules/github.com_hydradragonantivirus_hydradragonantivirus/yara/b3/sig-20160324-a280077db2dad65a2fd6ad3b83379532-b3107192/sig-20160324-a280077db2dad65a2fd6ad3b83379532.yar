rule sig_20160324_a280077db2dad65a2fd6ad3b83379532 {
  meta:
    description = "datamaliciousorder - file 20160324_a280077db2dad65a2fd6ad3b83379532.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84593dbea83ecf8196e7d1ca7b98f8825a29993fb82d6ce5fcd7b8e08a137d3f"

  strings:
    $s1  = "function kvC(JF) {var k = (1, 2, 3, 4, 5, JF); return k;};c = (QT) ? 14134 : 414234;qc = WScript[AL()](REc(tGz) + oU(Q0) + M0 + " ascii
    $s2  = "]();WScript[j + wVw(lv)](GA());var D = new this[At](),y = D[Xv(W0) + U0(y0) + mkJ(ic) + uX + MtH(sn) + KUb]();WScript[H(j) + rC(" ascii
    $s3  = ";var b = function gl() {return WScript[kP + KM(q) + fZV(Tt) + D0(E0) + VD(xw)](GAl + Z0(je) + WE(U) + G(boU));}();function PW(Sd" ascii
    $s4  = "function FN(M1){var _112crap = \"s\"; return \"\" + M1 + \"\";};function v0(Gxr){var _112crap = \"s\"; return \"\" + Gxr + \"\";" ascii
    $s5  = "+ s0(PNm) + eb(Hr) + g1(p1) + F0(nFJ) + Gn + yd(DDV), false);kZ[X0 + Lg(Bp)]();while (kZ[dt + Kf(PZK) + m0(r0)] < 4 ) {WScript[g" ascii
    $s6  = "){var _112crap = \"s\"; return \"\" + A0 + \"\";};var LE = \"GET\";function djT(AsD){var _112crap = \"s\"; return \"\" + AsD + " ascii
    $s7  = "E){b[L(mne) + tWM](SdE, 0, 0);};function ZzW(){return UZR(En) + sJ + MSw(XQ) + fa(OOS) + I(p);};function fU(Jq, Zgq){return Jq -" ascii
    $s8  = " && (QT == true)) ? true : false;};if (QT && IS() && sL){function uo() {return b[s + uq + j0(ksC) + jr(baA) + R0(D1) + Y + R1(Dq" ascii
    $s9  = "\\x73e\",q1 = \"c\\x6co\";function V2(i1){var _112crap = \"s\"; return \"\" + i1 + \"\";};function o0(dX){var _112crap = \"s\"; " ascii
    $s10 = "\\x32\";var En = HX0[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"t\"](1);function L(A){var _112crap = \"s\"; return \"\" + A + \"\";};var" ascii
    $s11 = " uN(HeZ){var _112crap = \"s\"; return \"\" + HeZ + \"\";};function T(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};functio" ascii
    $s12 = "{var _112crap = \"s\"; return \"\" + T1 + \"\";};var k0 = \"\\x73d\\x66\",p2 = \"fa\\x64f\\x61\";function uSA(MI){var _112crap =" ascii
    $s13 = "+ Z(xw)](CS); var gM = true; while (gM){try {kZ[djT(BMo) + uN(jY)](wjo(LE), l0(gS) + e + sIq(h2) + SNM(OE) + am(yGS) + lHW(nHG) " ascii
    $s14 = "JqE + \"\";};function i0(o){var _112crap = \"s\"; return \"\" + o + \"\";};var mKV = \"\\x6f\\x64y\",Nl = \"o\\x6eseB\";var wuE " ascii
    $s15 = "t){var _112crap = \"s\"; return \"\" + uLt + \"\";};function h(qF){var _112crap = \"s\"; return \"\" + qF + \"\";};function Xv(e" ascii
    $s16 = "(EPm){var _112crap = \"s\"; return \"\" + EPm + \"\";};function q0(uEe){var _112crap = \"s\"; return \"\" + uEe + \"\";};var v =" ascii
    $s17 = "return \"\" + wQ + \"\";};function s0(IE){var _112crap = \"s\"; return \"\" + IE + \"\";};function eb(U1){var _112crap = \"s\"; " ascii
    $s18 = "= DP[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"t\"](2);var mne = \"R\\x75\";function Z0(w){var _112crap = \"s\"; return \"\" + w + \"\"" ascii
    $s19 = " \"\";};function jr(m){var _112crap = \"s\"; return \"\" + m + \"\";};function R0(P){var _112crap = \"s\"; return \"\" + P + \"" ascii
    $s20 = "r cH = \"ll\\x69se\",Bw = \"\\x54CMi\";var h0 = \"\\x67\\x65tU\",iX = \"\\x44at\\x65\";function wVw(QJ){var _112crap = \"s\"; re" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}