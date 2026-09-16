rule sig_20160321_5b95fa0a2adde2534e4dc7309c04d758 {
  meta:
    description = "datamaliciousorder - file 20160321_5b95fa0a2adde2534e4dc7309c04d758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebbc6338f9666bc121e99c3f007212553572351c950b731f47c1d076417c12b6"

  strings:
    $s1  = "function AGjM(db){return db;};var gd = \"62\";var U = \"3681\";var H2 = \"21\\x38\";var VHNq = \"va\";var KXyOL = \"s\\x64f\";va" ascii
    $s2  = "* 1; P++){if (NYD() != 0){T = true;FzFFn = true;break;}}function i() {return T && FzFFn;};if (i()){eTh = DB[vIGgw(ofD) + (functi" ascii
    $s3  = "xlKEI)]();var uy = Y0[ZWc + MhCY + I(C) + (function rYLo(){return cji;}()) + kl]();WScript[HAHsy + (function rNh(){return jDmiW;" ascii
    $s4  = "n FBwTI;}()) + irU + lMcfk + (function s(){return sUzBM;}()) + (function Q(){return KBeQ;}()); aF = H(); FkOe = WScript[gaW(ZD) " ascii
    $s5  = ") + kl]();WScript[lwp(HAHsy) + jDmiW + (function TxPt(){return a1;}())](Hmz());var Y0 = new this[S0(vm) + cOjO(xlKEI)]();var ecM" ascii
    $s6  = " vxXxb(ApM) + (function Y1(){return h0;}())] < 4 ) {WScript[HAHsy + IDt(jDmiW) + (function FN(){return a1;}())](Hmz() * 10)};HZG" ascii
    $s7  = "wWC(){return vnKru;}());};function i0(NNR, aKa){return NNR - aKa;};function A(){return (function qS(){return ZD;}()) + (function" ascii
    $s8  = "\\x65B\\x6f\";var HYIN = \"s\\x70o\";var vTxw = \"e\";var jwcpF = uRM[\"charAt\"](5);var b0 = \"wri\\x74e\";function WQQZ(FvqiE)" ascii
    $s9  = "eturn Gj;};var OLP = \"\\x6aect\";var P0 = \"teO\\x62\";var ZD = \"Crea\";var DB = function DCGl() {return WScript[(function ibC" ascii
    $s10 = "Bh = false;} catch(e){};}BJ = WScript[A()]((function epyVm(){return ent;}()) + p0(Bu) + (function SXm(){return AUUZR;}()) + (fun" ascii
    $s11 = "JXli = \"ge\\x74\";var SEy = \"4DBUOq\";var fPsrM = \"ate\";var r0 = SEy[\"charAt\"](1);function lwp(vKRX){return vKRX;};functio" ascii
    $s12 = "= \"NSpznOeeS8\";var Ky = QYQf[\"charAt\"](4);var bdZiV = \"\\x52u\";function a(ZCgF){return ZCgF;};var Td = \"ell\";var hWdZM =" ascii
    $s13 = "s\";var cji = \"\\x6ed\";var C = \"co\";var MhCY = \"l\\x6cise\";var ZWc = \"get\\x4d\\x69\";function jorE(OB){return OB;};funct" ascii
    $s14 = "{return Hk;};var i1 = \"jMSpp\";var a1 = \"p\";var jDmiW = \"\\x6cee\";var HAHsy = i1[\"charAt\"](2);function I(Dj){return Dj;};" ascii
    $s15 = "UZR = \"B.St\";var Bu = F[\"charAt\"](5);var ent = \"ADO\";var i4 = \"e\\x70\";var V = \"\\x53\\x6ce\";function vxXxb(NF){return" ascii
    $s16 = "W(S){DB[DlsP(bdZiV) + MXfrm(Ky)](S, 0, 0);};function H(){return FMXwV(LrTg) + (function r(){return G;}()) + G0(nj) + (function H" ascii
    $s17 = "unt;}()) + (function MJH(){return S1;}()) + KXyOL : (function ybjPs(){return H2;}()) + U + AGjM(gd);}" fullword ascii
    $s18 = "())]();var FzGA = Y0[fDf(ZWc) + (function UASy(){return MhCY;}()) + (function dc(){return C;}()) + (function OH(){return cji;}()" ascii
    $s19 = " = Y0[MJ(ZWc) + (function sbQS(){return MhCY;}()) + JNyzG(C) + mqo(cji) + (function hgZ(){return kl;}())]();var bsMR = \"zq\";bs" ascii
    $s20 = "rn ZD;}()) + aQfRz(P0) + (function OPxWB(){return OLP;}())](a(VU) + XAB + (function AmZJ(){return hWdZM;}()) + Td);}();function " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}