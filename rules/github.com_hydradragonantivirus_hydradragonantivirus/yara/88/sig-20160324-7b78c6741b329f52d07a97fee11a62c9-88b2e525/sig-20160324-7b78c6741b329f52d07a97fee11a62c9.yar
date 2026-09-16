rule sig_20160324_7b78c6741b329f52d07a97fee11a62c9 {
  meta:
    description = "datamaliciousorder - file 20160324_7b78c6741b329f52d07a97fee11a62c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2978dd56ea9d3c144eb3acb97da476626fd348309ce2d3d69f1ba849988abb43"

  strings:
    $s1  = "se,sjz = \"CreateObject\";var ND = function oi() {return WScript[sjz](oJ + Ql(Z) + X0);}();var Nob = 123213,Gk = \"MSXML2.XMLHTT" ascii
    $s2  = "jP[q(Qx) + szk + i1 + I]();WScript[p](Vih());var jP = new this[lHi](),eQs = jP[WVV(Qx) + szk + i1 + R(I)]();var T = \"Pp\";T = X" ascii
    $s3  = "K = (Dr, O + os, nw(k1) + gT(mS), 2);};}function zT(G) {var nB = (1, 2, 3, 4, 5, G); return nB;};QZ = WScript[r()](WYE(bN) + dYF" ascii
    $s4  = " + gj](pbr + J) + d0 + yqf + aQq + sem;}; Oo = EoM(); Fs = WScript[sjz](Oo); var HK = 1; while (HK){try {Fs[K](cmE, JIj + SH(t) " ascii
    $s5  = " = 0;function B(){var jP = new this[lHi](),hrL = jP[Qx + szk + Tt(i1) + G0(I)]();WScript[p](Vih());var jP = new this[lHi](),k = " ascii
    $s6  = "function H(zUx){var _112crap = \"s\"; return \"\" + zUx + \"\";};var gn = \"\\x65\",dZr = \"c\\x6c\\x6fs\";function Z1(zq){var _" ascii
    $s7  = "var AG = 2123213,i = 0;function aRF(j){ND[Vmr(nk)](j, i, i);};function EoM(){return Gk;};function XwI(qI, XM){return qI - XM;};f" ascii
    $s8  = " {return ((F == true) && (F == VSG)) ? 1 : i;};if (F && oOx() && VSG){function Ix() {return ND[ZDc + WNH(QP) + C + gKk(i2) + kUT" ascii
    $s9  = "+ nmK + tV + AlT + KIQ, false);Fs[gRM]();Pac = \"Sleep\";while (Fs[FF + I0] < 4 ) {WScript[Pac](Vih() * 10)};HK = i;} catch(cAN)" ascii
    $s10 = "\\x74r\";var bN = \"ADO\\x44\";function nw(BkP){var _112crap = \"s\"; return \"\" + BkP + \"\";};function gT(JE){var _112crap = " ascii
    $s11 = "turn \"\" + t0 + \"\";};var KIQ = \"\\x75sy\",AlT = \"\\x74/k2\";var tV = \"ch.\\x6ee\",nmK = \"hc\\x68u\\x72\";var t = \":\\x2f" ascii
    $s12 = "!= i){F = true; e = \"07t9gasdf76ags\" + 123313 * T + e; VSG = true; e = \"07t9gasdf76ags\" + 123313 * T + e; break;}}function o" ascii
    $s13 = "function H(zUx){var _112crap = \"s\"; return \"\" + zUx + \"\";};var gn = \"\\x65\",dZr = \"c\\x6c\\x6fs\";function Z1(zq){var _" ascii
    $s14 = "; return \"\" + zq + \"\";};var o = \"\\x65\",D0 = \"ToF\\x69\\x6c\";var mK = \"S\\x61\\x76e\",Ke = \"ti\\x6fn\";var AiX = \"\\x" ascii
    $s15 = "= \"\\x25/\",pbr = \"%T\\x45\\x4d\\x50\";function WNH(cfe){var _112crap = \"s\"; return \"\" + cfe + \"\";};function gKk(oZ){var" ascii
    $s16 = ",RhP = \"\\x50\";var yt = \"\\x4d\\x4cH\\x54\\x54\",zR = \"L\\x32.X\";var i0 = \"M\\x53XM\";function Ql(pR){var _112crap = \"s\"" ascii
    $s17 = "\"; return \"\" + oZ + \"\";};var gj = \"g\\x73\",kUT = \"S\\x74rin\";var i2 = \"m\\x65nt\",C = \"ir\\x6f\\x6e\";var QP = \"dEn" ascii
    $s18 = "x6fd\\x79\";var m = \"\\x6f\\x6ese\",d1 = \"Re\\x73p\";var f = \"\\x65\",Y = \"w\\x72it\";function D(C0){var _112crap = \"s\"; r" ascii
    $s19 = "\";};var Z0 = \"typ\\x65\",DN = \"op\\x65n\";function WYE(cYk){var _112crap = \"s\"; return \"\" + cYk + \"\";};var Oml = \"\\x6" ascii
    $s20 = "12crap = \"s\"; return \"\" + IY + \"\";};function q(Sph){var _112crap = \"s\"; return \"\" + Sph + \"\";};function WVV(gwc){var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}