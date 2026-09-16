rule sig_20160324_01601c850e4179a2634436b8301d5b9c {
  meta:
    description = "datamaliciousorder - file 20160324_01601c850e4179a2634436b8301d5b9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "563088e6089d8b5de1366370f7c4deaa461beaa4087f03f6191454a73c73d9fc"

  strings:
    $s1  = "WScript[PC](c + rW(r0) + PQG);}();var t = 123213,o = \"MSXML2.XMLHTTP\";var Kp = 2123213,kXN = 0;function Sz(iYa){rh[RrB](iYa, k" ascii
    $s2  = "+ Mct + L(HN) + WdK(C) + sf + nB;}; TG = Od(); wSk = WScript[PC](TG); var Wx = 1; while (Wx){try {wSk[Ox](Glj, A + mHD + YU + p(" ascii
    $s3  = "E(Rn) + dDr + t0 + xN + qnc]();WScript[Ze](Kwj());var ffL = new this[yi](),Om = ffL[o0(Rn) + dDr + t0 + xN + qnc]();WScript[Ze](" ascii
    $s4  = "lM) + IEu + tM + P0, false);wSk[Q0]();am = \"Sleep\";while (wSk[Ypj + ftb(CUO) + VIF(g)] < 4 ) {WScript[am](Kwj() * 10)};Wx = kX" ascii
    $s5  = ", kXN);};function Od(){return o;};function k(as, Ar){return as - Ar;};function nEJ(){return PC;};/*@cc_on  @if (@_win32 || @_win" ascii
    $s6  = "var rN = \"c\\x6cose\",eYJ = \"\\x65\";var D0 = \"\\x54oFil\",fw = \"Sa\\x76e\";function rMH(bN){var _112crap = \"s\"; return \"" ascii
    $s7  = "rue) && (Q == KSw)) ? 1 : kXN;};if (Q && r() && KSw){function XZ() {return rh[ZYN(tj) + gRX + R(O) + pI + Us + rl](gg(P) + VBK) " ascii
    $s8  = "} catch(AWH){Wx = (w, F0 + bA, hN + RL, 2);};}function UJv(hKE) {var iT = (1, 2, 3, 4, 5, hKE); return iT;};URV = WScript[nEJ()]" ascii
    $s9  = "tion p(lRD){var _112crap = \"s\"; return \"\" + lRD + \"\";};var P0 = \"\\x69\\x73ua\",tM = \"\\x67/o\\x33\";var IEu = \"\\x73" ascii
    $s10 = "r b = \"\\x4dSX\\x4d\";function rW(Nr){var _112crap = \"s\"; return \"\" + Nr + \"\";};var PQG = \"Shel\\x6c\",r0 = \"ip\\x74.\"" ascii
    $s11 = "= \"\\x66ad\\x66\",w = \"\\x61\\x73d\\x66\\x61\";function ftb(Wfo){var _112crap = \"s\"; return \"\" + Wfo + \"\";};function VIF" ascii
    $s12 = "_112crap = \"s\"; return \"\" + bZW + \"\";};function WdK(RrX){var _112crap = \"s\"; return \"\" + RrX + \"\";};var nB = \"\\x78" ascii
    $s13 = "e\";var Ze = \"S\\x6c\\x65ep\";function uE(FY){var _112crap = \"s\"; return \"\" + FY + \"\";};function o0(e){var _112crap = \"s" ascii
    $s14 = ";var T = \"Res\\x70\",Yb = \"\\x65\";var I = \"wri\\x74\";function xuA(z){var _112crap = \"s\"; return \"\" + z + \"\";};var us " ascii
    $s15 = " + e + \"\";};function D(xue){var _112crap = \"s\"; return \"\" + xue + \"\";};var qnc = \"\\x73\",xN = \"\\x65co\\x6e\\x64\";va" ascii
    $s16 = "var rN = \"c\\x6cose\",eYJ = \"\\x65\";var D0 = \"\\x54oFil\",fw = \"Sa\\x76e\";function rMH(bN){var _112crap = \"s\"; return \"" ascii
    $s17 = "gasdf76ags\" + 123313 * kUx + QMO; KSw = true; QMO = \"07t9gasdf76ags\" + 123313 * kUx + QMO; break;}}function r() {return ((Q =" ascii
    $s18 = "Kwj());var ffL = new this[yi](),KY = ffL[Rn + dDr + D(t0) + xN + qnc]();var kUx = \"G\";kUx = k(Om, N);var QMO = \"TfL\";QMO = k" ascii
    $s19 = "p = \"s\"; return \"\" + r1 + \"\";};var g = \"\\x65\",CUO = \"s\\x74a\\x74\";var Ypj = \"re\\x61dy\",rO = \"Sle\\x65\\x70\";var" ascii
    $s20 = " = \"P\\x25/\",P = \"%TE\\x4d\";function ZYN(xUl){var _112crap = \"s\"; return \"\" + xUl + \"\";};function R(pph){var _112crap " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}