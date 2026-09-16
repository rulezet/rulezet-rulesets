rule sig_20160324_9b5c08864f09a4338c54bf114dbd2cd4 {
  meta:
    description = "datamaliciousorder - file 20160324_9b5c08864f09a4338c54bf114dbd2cd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdf8d096a185599c153dbaf6701abefd7f80776fe97ae2ec992dcdddf4c2c730"

  strings:
    $s1  = "function iG(RA){var _112crap = \"s\"; return \"\" + RA + \"\";};var if0 = \"0c6t4cBgzwa\",ckB = \"\\x6cose\";var Gwj = if0[\"cha" ascii
    $s2  = "ew this[xk(vh) + Nw + Py(Hrm)](),uaB = hHu[yqg(Gn) + dV + rk(G) + D0 + kmR(OHL) + qCk(dB) + dm]();WScript[V1](Dct());var hHu = n" ascii
    $s3  = "t\",Qc = \"e\\x4f\\x62j\\x65\";var skH = \"C\\x72e\\x61t\",NG = false;var ztN = function x() {return WScript[skH + OOc(Qc) + rhA" ascii
    $s4  = " Z = b(); s = WScript[j0(skH) + Qc + o(peN)](Z); var j = true; while (j){try {s[e2(dhh)](KAH(TpH), SDH(RBb) + PnP + r(s1) + IjU(" ascii
    $s5  = "ew this[vh + Nw + a(Hrm)](),sPG = hHu[d(Gn) + dV + M(G) + D0 + Do(OHL) + dB + Mw0(dm)]();WScript[V1](Dct());var hHu = new this[g" ascii
    $s6  = "r(dz) + ky(xY), true);};}function lT(AsV) {var QXc = (1, 2, 3, 4, 5, AsV); return QXc;};kE = (bdW) ? 14134 : 414234;J = WScript[" ascii
    $s7  = "r PnP = \"tt\",RBb = \"h\";function KAH(WUR){var _112crap = \"s\"; return \"\" + WUR + \"\";};var TpH = \"GET\";function e2(ZZ){" ascii
    $s8  = "1(RaN) + P0(xTL) + fK(yc);};function KQ(pxY, TRv){return pxY - TRv;};function tXP(){return Bol(skH) + V(Qc) + qkE(peN);};/*@cc_o" ascii
    $s9  = "ion DL() {return ((bdW == fQV) && (bdW == true)) ? true : false;};if (bdW && DL() && fQV){function Rk() {return ztN[Hq + Zqu + t" ascii
    $s10 = "fz(y1) + P2(FJV)] < 4 ) {WScript[E2(V1)](Dct() * 10)};j = false;} catch(ee){j = (M1(v0) + GEH(y2), s2(GYI) + T0(HyH) + M2(w), DA" ascii
    $s11 = " jPq + \"\";};function M2(qw){var _112crap = \"s\"; return \"\" + qw + \"\";};var TuQ = \"hNS5fZ\",w = \"\\x61sdf\";var HyH = \"" ascii
    $s12 = "[\"cha\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](4);function M1(Hj){var _112crap = \"s\"; return \"\" + Hj + \"\";};function GEH(b1){var" ascii
    $s13 = " + G1 + \"\";};function FPi(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function ji(W1){var _112crap = \"s\"; return \"\" " ascii
    $s14 = "function W(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};function Dod(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};" ascii
    $s15 = "= \"je\",Ki = \"\\x61\\x74\\x65Ob\";var Pi = \"Cre\";function zD(kl){var _112crap = \"s\"; return \"\" + kl + \"\";};function Mk" ascii
    $s16 = "turn \"\" + ht + \"\";};function B1(A1){var _112crap = \"s\"; return \"\" + A1 + \"\";};function T1(rQ){var _112crap = \"s\"; re" ascii
    $s17 = "\"\" + KIZ + \"\";};function Vz(l){var _112crap = \"s\"; return \"\" + l + \"\";};function M0(lUt){var _112crap = \"s\"; return " ascii
    $s18 = "ap = \"s\"; return \"\" + O + \"\";};function z1(dRH){var _112crap = \"s\"; return \"\" + dRH + \"\";};function HzB(A0){var _112" ascii
    $s19 = "Y = \"fa\",dz = \"\\x61fda\";function s2(H){var _112crap = \"s\"; return \"\" + H + \"\";};function T0(jPq){var _112crap = \"s\"" ascii
    $s20 = " fQ + \"\";};var FJV = \"\\x73tate\",y1 = \"ady\";var Uj = \"re\";function FJ(mQv){var _112crap = \"s\"; return \"\" + mQv + \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}