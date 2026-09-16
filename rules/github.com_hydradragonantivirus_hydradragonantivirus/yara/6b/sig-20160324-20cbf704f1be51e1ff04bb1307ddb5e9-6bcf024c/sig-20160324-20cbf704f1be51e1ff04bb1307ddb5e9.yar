rule sig_20160324_20cbf704f1be51e1ff04bb1307ddb5e9 {
  meta:
    description = "datamaliciousorder - file 20160324_20cbf704f1be51e1ff04bb1307ddb5e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f3d95f8f873ecc0ff945c0f06d48a2eb1745dad9ee7950ffa94e842dbd204c3"

  strings:
    $s1  = "Object\";var jM = function r() {return WScript[zFh](TO(J) + eX + qB);}();var Cv = 123213,XO = \"MSXML2.XMLHTTP\";var f = 2123213" ascii
    $s2  = "function WDD(nfh){var _112crap = \"s\"; return \"\" + nfh + \"\";};var lQU = \"\\x65\",D = \"c\\x6co\\x73\";function F1(G0){var " ascii
    $s3  = " + p0(N) + r0(ne) + c](k(LE) + Tq(w)) + Hr + sD + yv;}; wGr = I(); Nx = WScript[zFh](wGr); var B = 1; while (B){try {Nx[A](v0(jB" ascii
    $s4  = "r tmY = new this[e](),m = tmY[WEg + LnC(PzX) + Nl + Pg(Xz)]();WScript[UlQ + Av](Eq());var tmY = new this[e](),cTg = tmY[WEg + Pz" ascii
    $s5  = "X + Nl + Xz]();WScript[UlQ + Av](Eq());var tmY = new this[e](),hQF = tmY[WEg + PzX + Nl + Xz]();var XF = \"yW\";XF = o(cTg, m);v" ascii
    $s6  = " sn); return tjR;};P = WScript[d()](ao(T2) + H + mdm);wGr = P;wGr[(NpO(A))]();wGr[CY] = Rd(1);wGr[Sea(Y) + Fzu](Nx[N0 + Gze + O0" ascii
    $s7  = "a), k0 + S(k1) + Ruy + F0 + arq + RK + x(ZUt) + T1, false);Nx[Uk]();vb = \"Sleep\";while (Nx[L0 + GQu(t) + SOt] < 4 ) {WScript[v" ascii
    $s8  = " = 0;function T(g){jM[lTO](g, Fz, Fz);};function I(){return XO;};function o(cY, Rw){return cY - Rw;};function d(){return zFh;};/" ascii
    $s9  = "on DrP() {return ((oHg == true) && (oHg == Ft)) ? 1 : Fz;};if (oHg && DrP() && Ft){function ub() {return jM[B0(O) + G(aAu) + pIU" ascii
    $s10 = "function WDD(nfh){var _112crap = \"s\"; return \"\" + nfh + \"\";};var lQU = \"\\x65\",D = \"c\\x6co\\x73\";function F1(G0){var " ascii
    $s11 = "+ VZp + \"\";};function p0(Zx){var _112crap = \"s\"; return \"\" + Zx + \"\";};function r0(BJ){var _112crap = \"s\"; return \"\"" ascii
    $s12 = "5/\",LE = \"\\x25\\x54\\x45MP\";function B0(F){var _112crap = \"s\"; return \"\" + F + \"\";};function G(VZp){var _112crap = \"s" ascii
    $s13 = "= \"Slee\\x70\";var Uk = \"s\\x65nd\";function S(h1){var _112crap = \"s\"; return \"\" + h1 + \"\";};function x(K){var _112crap " ascii
    $s14 = "r k1 = \":\\x2f\\x2fs\\x74\",k0 = \"htt\\x70\";function v0(w0){var _112crap = \"s\"; return \"\" + w0 + \"\";};var jBa = \"\\x47" ascii
    $s15 = " = \"\\x73\\x64\\x66\",bG = \"\\x66\\x61df\\x61\";function Thz(Jvf){var _112crap = \"s\"; return \"\" + Jvf + \"\";};var uk = \"" ascii
    $s16 = " = \"s\"; return \"\" + nb + \"\";};var Fzu = \"\\x65\",Y = \"w\\x72i\\x74\";var CY = \"\\x74\\x79\\x70\\x65\",IZ = \"o\\x70en\"" ascii
    $s17 = ";function k(jRz){var _112crap = \"s\"; return \"\" + jRz + \"\";};function Tq(l){var _112crap = \"s\"; return \"\" + l + \"\";};" ascii
    $s18 = "z){oHg = true; GjZ = \"07t9gasdf76ags\" + 123313 * XF + GjZ; Ft = true; GjZ = \"07t9gasdf76ags\" + 123313 * XF + GjZ; break;}}fu" ascii
    $s19 = "v = \"\\x70\";var UlQ = \"Sle\\x65\";function LnC(J0){var _112crap = \"s\"; return \"\" + J0 + \"\";};function Pg(s){var _112cra" ascii
    $s20 = ";var huf = \"\\x48TTP\",C = \"2.XM\\x4c\";var pi = \"MS\\x58ML\";function TO(swU){var _112crap = \"s\"; return \"\" + swU + \"\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}