rule sig_20160324_0823849bfa99c04723569bd9d12f06e6 {
  meta:
    description = "datamaliciousorder - file 20160324_0823849bfa99c04723569bd9d12f06e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f78586220d5eca766fdc721dffa36198f004aa6b8bd11149f35c9c8074800f31"

  strings:
    $s1  = "var BC = \"\\x65\",l0 = \"\\x63los\";function wcD(FOX){var _112crap = \"s\"; return \"\" + FOX + \"\";};function T0(Ke){var _112" ascii
    $s2  = "o = function w() {return WScript[oyy](Zo + DA + eKW);}();var js = 123213,lVI = \"MSXML2.XMLHTTP\";var q = 2123213,ht = 0;functio" ascii
    $s3  = "this[Ed(wra)](),RU = P[T + s + Fb0(Ero) + rhR]();WScript[Rc(khu)](kl());var P = new this[wra](),OtC = P[T + HW(s) + Ero + F0(rhR" ascii
    $s4  = " Q1(D) + D0 + BVo + n0 + oLn + c0, false);Nls[EHJ(yG)]();Mp = \"Sleep\";while (Nls[Pn + h0 + a0] < 4 ) {WScript[Mp](kl() * 10)};" ascii
    $s5  = ")]();WScript[qKh(khu)](kl());var P = new this[j(wra)](),eU = P[Xr(T) + fsO(s) + Ero + rhR]();var n = \"r\";n = TWl(OtC, RU);var " ascii
    $s6  = "+ aZq) + oQ + Q0 + U0 + v0(FTN);}; U = Ui(); Nls = WScript[oyy](U); var v = 1; while (v){try {Nls[eUt(F1)](dwL(fKF), Buq + fdQ +" ascii
    $s7  = "UDz(seV){Io[w0](seV, ht, ht);};function Ui(){return lVI;};function TWl(jrP, K){return jrP - K;};function AUH(){return oyy;};/*@c" ascii
    $s8  = " == true) && (ck == u)) ? 1 : ht;};if (ck && hc() && u){function lV() {return Io[h(i) + q1(Iee) + VMF(e0) + d + vqN + EE](hX(H) " ascii
    $s9  = "4a\\x74\";var Pn = \"read\\x79\",Oyu = \"S\\x6c\\x65e\\x70\";function EHJ(zn){var _112crap = \"s\"; return \"\" + zn + \"\";};va" ascii
    $s10 = "= ht;} catch(IH){v = (y(a1) + DKB, nvw + X, l + iBp, 2);};}function a(CC) {var Q = (1, 2, 3, 4, 5, CC); return Q;};tX = WScript[" ascii
    $s11 = "\\x55\";function Ed(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function j(AKq){var _112crap = \"s\"; return \"\" + AKq " ascii
    $s12 = "\\x64\\x66a\";function y(zhK){var _112crap = \"s\"; return \"\" + zhK + \"\";};var DKB = \"\\x61\",a1 = \"as\\x64f\";var a0 = \"" ascii
    $s13 = " = \"\\x53\\x6ce\\x65p\";function Fb0(fP){var _112crap = \"s\"; return \"\" + fP + \"\";};function HW(Ck){var _112crap = \"s\"; " ascii
    $s14 = ";function Q1(wCC){var _112crap = \"s\"; return \"\" + wCC + \"\";};var c0 = \"\\x73l2s\\x64\",oLn = \"\\x6fm/a\";var n0 = \"ey" ascii
    $s15 = "= \"kF\";F = TWl(eU, OtC);return TWl(n, F);}var ck = false,u = false;for (var zC = ht; zC < kl() * 1; zC++){if (ekA() != ht){ck " ascii
    $s16 = " _112crap = \"s\"; return \"\" + Gk + \"\";};var aZq = \"P\\x25\\x2f\",H = \"%T\\x45M\";function h(Ej){var _112crap = \"s\"; ret" ascii
    $s17 = "true; F = \"07t9gasdf76ags\" + 123313 * n + F; u = true; F = \"07t9gasdf76ags\" + 123313 * n + F; break;}}function hc() {return " ascii
    $s18 = "\";};function q1(ALR){var _112crap = \"s\"; return \"\" + ALR + \"\";};function VMF(CD){var _112crap = \"s\"; return \"\" + CD +" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + Qd + \"\";};var FTN = \"\\x65\",U0 = \"A\\x2eex\";var Q0 = \"\\x37K\\x72Y\",oQ = \"E05\\x31\";" ascii
    $s20 = "var BC = \"\\x65\",l0 = \"\\x63los\";function wcD(FOX){var _112crap = \"s\"; return \"\" + FOX + \"\";};function T0(Ke){var _112" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}