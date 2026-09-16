rule sig_20160324_80be479a5767b2d704becaf9b99127ea {
  meta:
    description = "datamaliciousorder - file 20160324_80be479a5767b2d704becaf9b99127ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e8f96a17b3f6380eaad7f728a08cad913a2ac0c8047832242919a49758189c"

  strings:
    $s1  = "var wmp = \"cl\\x6fse\",K0 = \"l\\x65\";var zJy = \"\\x54oFi\",Bi = \"\\x53\\x61ve\";function a0(U){var _112crap = \"s\"; return" ascii
    $s2  = "jLs = \"CreateObject\";var H = function u() {return WScript[jLs](Bzu + UT + zCp);}();var xX = 123213,ZK = \"MSXML2.XMLHTTP\";var" ascii
    $s3  = "aZ) + XwW, oPa + Dmz, 2);};}function h(zxr) {var A = (1, 2, 3, 4, 5, zxr); return A;};GD = WScript[q()](mN + Mc(J1) + bIW);PEw =" ascii
    $s4  = " md + y + pA(Mi);}; PEw = X(); M = WScript[jLs](PEw); var nVV = 1; while (nVV){try {M[wsg](aA(dGC), s0 + zDC(jdm) + E + LJA(K) +" ascii
    $s5  = " + lNh]();WScript[ru](w());var l = new this[JOk](),YF = l[XQL + BJ + F(niW) + lNh]();var r = \"R\";r = Bm(a, DXX);var AlK = \"j" ascii
    $s6  = "){var l = new this[JOk](),DXX = l[fbD(XQL) + J0(BJ) + niW + lNh]();WScript[ru](w());var l = new this[JOk](),a = l[XQL + BJ + niW" ascii
    $s7  = "= 2123213,J = 0;function c(am){H[I](am, J, J);};function X(){return ZK;};function Bm(S, dkm){return S - dkm;};function q(){retur" ascii
    $s8  = "XA == true) && (SXA == P)) ? 1 : J;};if (SXA && boP() && P){function Fiq() {return H[f + l0 + ZHy + WHN + yX](bj + N0) + C + Q +" ascii
    $s9  = " wl + r0 + r1, false);M[t]();wn = \"Sleep\";while (M[Z2 + hX] < 4 ) {WScript[wn](w() * 10)};nVV = J;} catch(X0){nVV = (dG + Rs, " ascii
    $s10 = "5\",Vv = \"ope\\x6e\";function Mc(w1){var _112crap = \"s\"; return \"\" + w1 + \"\";};var bIW = \"\\x65am\",J1 = \".S\\x74\\x72" ascii
    $s11 = "var wmp = \"cl\\x6fse\",K0 = \"l\\x65\";var zJy = \"\\x54oFi\",Bi = \"\\x53\\x61ve\";function a0(U){var _112crap = \"s\"; return" ascii
    $s12 = "var Z3 = \"\\x69on\",jdI = \"po\\x73it\";function miI(krC){var _112crap = \"s\"; return \"\" + krC + \"\";};function wi(BxF){var" ascii
    $s13 = "\";};function F(w0){var _112crap = \"s\"; return \"\" + w0 + \"\";};var lNh = \"\\x63o\\x6ed\\x73\",niW = \"llis\\x65\";var BJ =" ascii
    $s14 = "= \"Sl\\x65ep\";function fbD(GRi){var _112crap = \"s\"; return \"\" + GRi + \"\";};function J0(QU){var _112crap = \"s\"; return " ascii
    $s15 = "K = \"07t9gasdf76ags\" + 123313 * r + AlK; P = true; AlK = \"07t9gasdf76ags\" + 123313 * r + AlK; break;}}function boP() {return" ascii
    $s16 = "ion aA(jq){var _112crap = \"s\"; return \"\" + jq + \"\";};var dGC = \"\\x47ET\",wsg = \"\\x6fpen\";function pA(GdX){var _112cra" ascii
    $s17 = "fDB\",Dmz = \"\\x66a\";var oPa = \"af\\x64a\";function z(rA){var _112crap = \"s\"; return \"\" + rA + \"\";};var XwW = \"\\x61sd" ascii
    $s18 = "K = Bm(YF, a);return Bm(r, AlK);}var SXA = false,P = false;for (var YBg = J; YBg < w() * 1; YBg++){if (Or() != J){SXA = true; Al" ascii
    $s19 = "; return \"\" + jM + \"\";};var tf = \"\\x65\",S0 = \"wri\\x74\";function Y(XT){var _112crap = \"s\"; return \"\" + XT + \"\";};" ascii
    $s20 = "64\";function zDC(Qm){var _112crap = \"s\"; return \"\" + Qm + \"\";};function LJA(Ahb){var _112crap = \"s\"; return \"\" + Ahb " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}