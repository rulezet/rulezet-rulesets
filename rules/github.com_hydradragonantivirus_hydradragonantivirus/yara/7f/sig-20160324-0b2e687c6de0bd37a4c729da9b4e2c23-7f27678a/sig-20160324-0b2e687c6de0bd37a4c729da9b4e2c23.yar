rule sig_20160324_0b2e687c6de0bd37a4c729da9b4e2c23 {
  meta:
    description = "datamaliciousorder - file 20160324_0b2e687c6de0bd37a4c729da9b4e2c23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ba3484f53cb0a2f760defdc421afc5dd3aad21ae2fd0f99678687e15784bf15"

  strings:
    $s1  = "var Z = \"\\x65\",yo = \"c\\x6cos\";var NvX = \"l\\x65\",C1 = \"T\\x6f\\x46i\";var XK = \"Sav\\x65\";function J(Opp){var _112cra" ascii
    $s2  = "ar bXP = false,sTl = \"CreateObject\";var u = function zv() {return WScript[sTl](txB + fZ(qse) + mI);}();var QT = 123213,cj = \"" ascii
    $s3  = " + mFS + q + ApM](Rg + b1) + Br(b2) + oFd + JV + Di;}; RwG = IBz(); u0 = WScript[sTl](RwG); var Q = 1; while (Q){try {u0[j](BN, " ascii
    $s4  = "uv + f0(WZx) + ZPH(m) + H + Vr + JPz + e0 + j0, false);u0[Q0]();Xd = \"Sleep\";while (u0[W2(C0) + I + b3(VD)] < 4 ) {WScript[Xd]" ascii
    $s5  = "ar oX = 0,e = 0;function W(){var FHl = new this[U(Vzh)](),AsZ = FHl[A0 + SX + Qx(OW) + pS(dTV)]();WScript[yp](r());var FHl = new" ascii
    $s6  = " this[Vzh](),yA = FHl[A0 + SX + OW + dTV]();WScript[yp](r());var FHl = new this[Vzh](),W0 = FHl[A0 + SX + OW + dTV]();var oX = " ascii
    $s7  = " = \"li\\x73e\\x63\";var SX = \"\\x43Mil\",A0 = \"getU\\x54\";function U(B){var _112crap = \"s\"; return \"\" + B + \"\";};var V" ascii
    $s8  = "ML2.XMLHTTP\";var cr = 2123213,h = 0;function sOa(CSW){u[Vio](CSW, h, h);};function IBz(){return cj;};function G(p, De){return p" ascii
    $s9  = "SJ\";oX = G(yA, AsZ);var e = \"yIo\";e = G(W0, yA);return G(oX, e);}var Uzv = false,Qnm = false;for (var iQG = h; iQG < r() * 1;" ascii
    $s10 = "var _112crap = \"s\"; return \"\" + nn + \"\";};var VD = \"t\\x65\",I = \"\\x79sta\";var C0 = \"rea\\x64\",dlJ = \"\\x70\";var b" ascii
    $s11 = "\",vf = \"fa\\x64f\\x61\";var iPG = \"\\x61\",n = \"as\\x64f\";function W2(Ris){var _112crap = \"s\"; return \"\" + Ris + \"\";}" ascii
    $s12 = "G++){if (W() != h){Uzv = true; e = \"07t9gasdf76ags\" + 123313 * oX + e; Qnm = true; e = \"07t9gasdf76ags\" + 123313 * oX + e; b" ascii
    $s13 = "v){var _112crap = \"s\"; return \"\" + Bv + \"\";};function pS(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};var dTV = \"" ascii
    $s14 = " = \"A\\x44\\x4fD\",xV = \"\\x61\";var Vs = \"\\x61fd\\x61f\";function CJk(IDe){var _112crap = \"s\"; return \"\" + IDe + \"\";}" ascii
    $s15 = "\"\" + Opp + \"\";};var lM = \"ti\\x6fn\",F = \"pos\\x69\";function TEj(nhD){var _112crap = \"s\"; return \"\" + nhD + \"\";};va" ascii
    $s16 = "0\",uv = \"htt\\x70:\";var BN = \"G\\x45T\",j = \"ope\\x6e\";function Br(JT){var _112crap = \"s\"; return \"\" + JT + \"\";};var" ascii
    $s17 = " \"s\\x65nd\";function f0(ef){var _112crap = \"s\"; return \"\" + ef + \"\";};function ZPH(nyJ){var _112crap = \"s\"; return \"" ascii
    $s18 = ";}}function ao() {return ((Uzv == true) && (Uzv == Qnm)) ? 1 : h;};if (Uzv && ao() && Qnm){function SCA() {return u[D + RT + ivX" ascii
    $s19 = "io = \"\\x52\\x75n\";var l = \"\\x50\",SL = \"ML\\x48\\x54T\";var N = \"L\\x32.X\",Jk = \"M\\x53XM\";function fZ(jGz){var _112cr" ascii
    $s20 = "\";var t = \"con\\x64\",aD = \"lli\\x73e\";var k = \"T\\x43Mi\",b = \"\\x67\\x65tU\";var p0 = \"D\\x61\\x74e\",yp = \"\\x53\\x6c" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}