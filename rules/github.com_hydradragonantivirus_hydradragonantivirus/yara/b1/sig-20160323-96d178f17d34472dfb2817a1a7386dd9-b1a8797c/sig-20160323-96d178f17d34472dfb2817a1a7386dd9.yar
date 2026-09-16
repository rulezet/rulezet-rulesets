rule sig_20160323_96d178f17d34472dfb2817a1a7386dd9 {
  meta:
    description = "datamaliciousorder - file 20160323_96d178f17d34472dfb2817a1a7386dd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb1918b408c6b9766bf444a74013535ae0b371561c5859b7da38ba2a6db503e"

  strings:
    $s1  = "function Hl(d1){var _112crap = \"s\"; return \"\" + d1 + \"\";};var RY = \"\\x63los\\x65\";function O(znc){var _112crap = \"s\";" ascii
    $s2  = "= \"s\"; return \"\" + vqJ + \"\";};function pL(d){var _112crap = \"s\"; return \"\" + d + \"\";};var l = \".exe\",lD = \"\\x41" ascii
    $s3  = "\\x72\";var WSC = false,F0 = function X() {return WScript[rjW(Uf) + PP + vnD(v) + UIc(Vqf) + A0](K(Qy) + PfL(R) + JjC(SV) + y0(p" ascii
    $s4  = "lD) + pL(l);}; wOo = J(); Q = WScript[Uf + PP + y(v) + Vqf + bC(A0)](wOo); var F = true; while (F){try {Q[rAp(m) + w(pSt)](pt, c" ascii
    $s5  = ") + N0(D) + PG(sFH) + RAX + Qg(pjl)]();WScript[vcz + yfl(j0)](L());var h = new this[J0(sE)](),tfm = h[xcw(Sc) + xLT + D0(D) + dE" ascii
    $s6  = "true);};}function SB(aCv) {var OAl = (1, 2, 3, 4, 5, aCv); return OAl;};wk = (rC) ? 14134 : 414234;kuE = WScript[I()](Pla(Y0) + " ascii
    $s7  = "m(sFH) + DR(RAX) + pjl]();WScript[rN(vcz) + b(j0)](L());var h = new this[sE](),VfX = h[u(Sc) + wmo(xLT) + msh(D) + evV(sFH) + RA" ascii
    $s8  = " + 123313 * wk + Uy; break;}}function GK() {return ((rC == Xi) && (rC == true)) ? true : false;};if (rC && GK() && Xi){function " ascii
    $s9  = "v(h1) + nXg(diO)] < 4 ) {WScript[Gfo(vcz) + j0](L() * 10)};F = false;} catch(Vip){F = (N1, MjZ(QN) + jBl(GW), IQv(RE) + gM(T1), " ascii
    $s10 = "fl(C){var _112crap = \"s\"; return \"\" + C + \"\";};function rN(K1){var _112crap = \"s\"; return \"\" + K1 + \"\";};function b(" ascii
    $s11 = "X + R0(pjl)]();var wk = \"ZWT\";wk = A(tfm, ye);var Uy = \"cS\";Uy = A(VfX, tfm);return A(wk, Uy);}var rC = false,Xi = false;for" ascii
    $s12 = "N){var _112crap = \"s\"; return \"\" + ibN + \"\";};function msh(hm){var _112crap = \"s\"; return \"\" + hm + \"\";};function ev" ascii
    $s13 = "+ \"\";};function D0(sNA){var _112crap = \"s\"; return \"\" + sNA + \"\";};function dEm(tl){var _112crap = \"s\"; return \"\" + " ascii
    $s14 = "//vl\";var yk = \"ht\\x74p\",pt = \"GE\\x54\";function rAp(KUR){var _112crap = \"s\"; return \"\" + KUR + \"\";};function w(WT){" ascii
    $s15 = ";function sMv(ktx){var _112crap = \"s\"; return \"\" + ktx + \"\";};function MEf(a){var _112crap = \"s\"; return \"\" + a + \"\"" ascii
    $s16 = ");}();function vd(IfC){F0[HL(fHh)](IfC, 0, 0);};function J(){return Vjl(cg) + y1(XgA) + q(L0) + pN + Q0(Ec) + FI(Pr);};function " ascii
    $s17 = "0 = \"\\x53l\\x65e\";function L1(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};function QO(G){var _112crap = \"s\"; return" ascii
    $s18 = " sta = paO[\"\"+\"\\x63\"+\"ha\"+\"\\x72\"+\"At\"](1),uO = \"\\x6fp\\x65\";function Pla(Ay){var _112crap = \"s\"; return \"\" + " ascii
    $s19 = "eturn \"\" + D1 + \"\";};var pSt = \"en\",m = \"op\";var XcB = \"\\x65\\x63\\x74\",ppS = \"eOb\\x6a\";var YH = \"\\x43rea\\x74\"" ascii
    $s20 = "; return \"\" + tVu + \"\";};function y(Hn){var _112crap = \"s\"; return \"\" + Hn + \"\";};function bC(j){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}