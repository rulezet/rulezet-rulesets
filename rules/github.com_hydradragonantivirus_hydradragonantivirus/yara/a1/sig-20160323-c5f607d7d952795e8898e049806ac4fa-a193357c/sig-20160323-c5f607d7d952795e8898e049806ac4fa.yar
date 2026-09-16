rule sig_20160323_c5f607d7d952795e8898e049806ac4fa {
  meta:
    description = "datamaliciousorder - file 20160323_c5f607d7d952795e8898e049806ac4fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eef88864e32dc164497bdc2e153faf6040b66b6e7177e062d5e093f97519941"

  strings:
    $s1  = "iN) + w0(U2) + K3(S0), true);};}function R(q) {var t = (1, 2, 3, 4, 5, q); return t;};dQY = (PF) ? 14134 : 414234;ES = WScript[P" ascii
    $s2  = "rn WScript[W(Af) + dz(efe) + ML + stG](l(YEb) + JSS(eG) + SYj);}();function jsO(Lc){tFp[tlF](Lc, 0, 0);};function REz(){return Q" ascii
    $s3  = "function gJO(uqk){var _112crap = \"s\"; return \"\" + uqk + \"\";};var fc = \"eXY1\",FIF = fc[\"charA\"+\"\\x74\"+\"\"](0);var X" ascii
    $s4  = " new this[Pkt(R0) + l0(J)](),bQ = Y[BNQ + Mfo + D(Rl) + XWW + dWn(Xck) + k(Zop)]();WScript[z0 + O0](S());var Y = new this[R0 + j" ascii
    $s5  = "ew this[K0(R0) + iT(J)](),sW = Y[JKa(BNQ) + KzS(Mfo) + J0(Rl) + U(XWW) + qlv(Xck) + Srx(Zop)]();WScript[z0 + E(O0)](S());var Y =" ascii
    $s6  = "GF(a) + y(vb) + q0(lQx) + ZpD + K(ngJ);};function c(p, A){return p - A;};function P(){return O(Af) + efe + ML + AL(stG);};/*@cc_" ascii
    $s7  = " B) && (PF == true)) ? true : false;};if (PF && MAe() && B){function b() {return tFp[ZFF + MIJ + KUI(quU) + Ies(eoh) + u0 + eG0(" ascii
    $s8  = "HF) + A0 + e0(Qw) + G] < 4 ) {WScript[z0 + d1(O0)](S() * 10)};AC = false;} catch(L){AC = (Gx(H) + wUn + Z0, mXs + D0(IWB), BIu(Y" ascii
    $s9  = "BZ(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};function rg(jQ){var _112crap = \"s\"; return \"\" + jQ + \"\";};var m = " ascii
    $s10 = "12crap = \"s\"; return \"\" + LKx + \"\";};function dh(fD){var _112crap = \"s\"; return \"\" + fD + \"\";};function nPR(GRj){var" ascii
    $s11 = "rap = \"s\"; return \"\" + F + \"\";};function U(OA){var _112crap = \"s\"; return \"\" + OA + \"\";};function qlv(zP){var _112cr" ascii
    $s12 = "waJ = \"eObj\",i0 = \"Cr\\x65a\\x74\";function Ij(mD){var _112crap = \"s\"; return \"\" + mD + \"\";};function y0(LR){var _112cr" ascii
    $s13 = "hi){var _112crap = \"s\"; return \"\" + Khi + \"\";};function KzS(u){var _112crap = \"s\"; return \"\" + u + \"\";};function J0(" ascii
    $s14 = "1 + \"\";};function L1(PrB){var _112crap = \"s\"; return \"\" + PrB + \"\";};function e0(HdR){var _112crap = \"s\"; return \"\" " ascii
    $s15 = "9gasdf76ags\" + 123313 * dQY + oYG; B = true; oYG = \"07t9gasdf76ags\" + 123313 * dQY + oYG; break;}}function MAe() {return ((PF" ascii
    $s16 = "\"s\"; return \"\" + GRj + \"\";};function ejN(tV){var _112crap = \"s\"; return \"\" + tV + \"\";};function Jrd(WWF){var _112cra" ascii
    $s17 = "turn \"\" + gBe + \"\";};function oV(js){var _112crap = \"s\"; return \"\" + js + \"\";};function PBZ(K4){var _112crap = \"s\"; " ascii
    $s18 = "nction K1(yId){var _112crap = \"s\"; return \"\" + yId + \"\";};function mb(Db){var _112crap = \"s\"; return \"\" + Db + \"\";};" ascii
    $s19 = "eturn \"\" + Opk + \"\";};var bSv = \"/\",suy = \"P%\";var dd = \"\\x25T\\x45M\";function KUI(Z){var _112crap = \"s\"; return \"" ascii
    $s20 = "\"\\x74\"+\"\"](3);var frv = \"\\x62j\",Vb = \"eate\\x4f\";var DtA = \"Cr\";function QGF(yUE){var _112crap = \"s\"; return \"\" " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}