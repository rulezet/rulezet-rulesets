rule sig_20160323_8a53ae84640386e0525395d524b0d64a {
  meta:
    description = "datamaliciousorder - file 20160323_8a53ae84640386e0525395d524b0d64a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b973bdc9b6263e7e08ce5c62f8e6af5501e9b3d25f452642b96e9a86418b36e"

  strings:
    $s1  = "function m0(lOo){var _112crap = \"s\"; return \"\" + lOo + \"\";};function a3(y0){var _112crap = \"s\"; return \"\" + y0 + \"\";" ascii
    $s2  = "* NY + tP; c = true; tP = \"07t9gasdf76ags\" + 123313 * NY + tP; break;}}function iMv() {return ((A == c) && (A == true)) ? true" ascii
    $s3  = "(){var eG = new this[ZH(u)](),zPN = eG[u1(njd) + lQ(PK) + Kj(DXQ) + u0 + yo(T1) + RFW(xAS)]();WScript[mM(Cx)](SV());var eG = new" ascii
    $s4  = ";var sDg = \"\\x65a\",Tdx = \"Cr\";var lb = false,rm = function hm() {return WScript[yPm(Tdx) + o(sDg) + oPm + df + uJq(Xg) + Yd" ascii
    $s5  = "Mf) + z + nkk(Rpd) + D1(pX), false);T[Xfv(V0) + VYr]();while (T[Pr(CU) + JHm + MR(VYn)] < 4 ) {WScript[C(Cx)](SV() * 10)};LWM = " ascii
    $s6  = " this[bW(u)](),Ws = eG[wAr(njd) + PK + GUq(DXQ) + un(u0) + WyH(T1) + nB(xAS)]();WScript[S(Cx)](SV());var eG = new this[u](),BJ =" ascii
    $s7  = ", 4, 5, waG); return R0;};NY = (A) ? 14134 : 414234;c0 = WScript[eDG()](r2 + D2(TFg) + MB(gu) + Bj(R4) + eq + BjA);Zua = c0;tP =" ascii
    $s8  = "ction Ccf(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};var rw = \"Ixpu3\",Vpn = \"e\";var LzY = rw[\"ch\"+\"\\x61\"+\"rAt" ascii
    $s9  = "SmD = \"T\\x45\",Cp = jT[\"ch\"+\"\\x61\"+\"rAt\"](3);function tGM(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};function " ascii
    $s10 = "112crap = \"s\"; return \"\" + z0 + \"\";};var r3 = \"AMnBjt2xxlh\",HR = \"\\x69on\";var j = r3[\"ch\"+\"\\x61\"+\"rAt\"](5),N0 " ascii
    $s11 = "dA + \"\";};var H = \"K92RAQ5oz\",B = \"u\\x6e\";var Z = H[\"ch\"+\"\\x61\"+\"rAt\"](3);function T0(Py){var _112crap = \"s\"; re" ascii
    $s12 = "on P(kHr){var _112crap = \"s\"; return \"\" + kHr + \"\";};var QnQ = \"pzUKelZZQ5t\",Faj = QnQ[\"ch\"+\"\\x61\"+\"rAt\"](5);var " ascii
    $s13 = " \"r\",VYn = \"\\x74a\\x74e\";var JHm = \"e\\x61dy\\x73\",CU = i2[\"ch\"+\"\\x61\"+\"rAt\"](0);function Xfv(nK){var _112crap = " ascii
    $s14 = "il\\x6ci\";var PK = \"\\x54\\x43\",njd = \"get\\x55\";function ZH(r){var _112crap = \"s\"; return \"\" + r + \"\";};function bW(" ascii
    $s15 = "ar kBG = G1[\"ch\"+\"\\x61\"+\"rAt\"](3),Kf = \"af\";function Vc(sYv){var _112crap = \"s\"; return \"\" + sYv + \"\";};function " ascii
    $s16 = "var _112crap = \"s\"; return \"\" + lU + \"\";};var ei = \"GET\";function tv(wZF){var _112crap = \"s\"; return \"\" + wZF + \"\"" ascii
    $s17 = "12crap = \"s\"; return \"\" + MDw + \"\";};var b = \"bG\",f0 = \"\\x74\";var f = \"c\",Xg = \"je\";var df = b[\"ch\"+\"\\x61\"+" ascii
    $s18 = "h\"+\"\\x61\"+\"rAt\"](0),P2 = \"wri\";function R6(Hi){var _112crap = \"s\"; return \"\" + Hi + \"\";};var F = \"e\",HtB = \"ty" ascii
    $s19 = "5 + \"\";};function Bj(b3){var _112crap = \"s\"; return \"\" + b3 + \"\";};var qmu = \".V2G\",B0 = \"2hmUKT5\";var BjA = B0[\"ch" ascii
    $s20 = "p) + EsA + l + mxL(k);};function wy(mo, Gs){return mo - Gs;};function eDG(){return O(Tdx) + TU(sDg) + oPm + Nu(df) + Xg + w(f) +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}