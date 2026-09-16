rule sig_20160321_f8a1aa54f13e00bd6237bc5c4eb19b87 {
  meta:
    description = "datamaliciousorder - file 20160321_f8a1aa54f13e00bd6237bc5c4eb19b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0b3afffef06d05079869a101ccc7882315241e2675ef92c0bc2c27c11191de"

  strings:
    $s1  = "var SHG = \"2c\";var xTHC = SHG[\"charAt\"](0);var ljvDn = \"3\\x3681\\x36\";var IAdnC = \"2\\x318\";function H(Vda){return Vda;" ascii
    $s2  = " new this[R(xXuoF) + gt]();var iVnvw = y[ycQa(lb) + (function dH(){return x0;}()) + Aj(IsZq) + K(Dmtv)]();WScript[fU(Apo) + (fun" ascii
    $s3  = "n WScript[IwRXG(Zla) + YtL + wjmTL(ari) + rl(G) + O0(hDn)]((function bF(){return oXj;}()) + (function gfGej(){return m;}()) + ve" ascii
    $s4  = "iwv;}()) + qingY(wxDx)] < 4 ) {WScript[LSS(Apo) + (function shtH(){return gGq;}()) + (function yrQzo(){return DjNEd;}())](Vv() *" ascii
    $s5  = "Zq + (function ThoU(){return Dmtv;}())]();WScript[sKd(Apo) + gGq + (function RT(){return DjNEd;}())](Vv());var y = new this[jUl(" ascii
    $s6  = "+ (function hVQ(){return j;}()); Id = YS(); SF = WScript[Z(Zla) + mWU(YtL) + (function krP(){return ari;}()) + G + hDn](Id); var" ascii
    $s7  = "turn D;}()) + (function McWS(){return jfez;}())] = 0;W[pKU + GPxJ(LLOg) + ilU + xOeXw(pT)](DW, 2 );W[BSuV(bq)]();uSue(DW);uz = " ascii
    $s8  = "ZG + OSbc + tt + iBCH + (function g(){return F;}());};function Y(Uw, cMNh){return Uw - cMNh;};function HQq(){return Zla + (funct" ascii
    $s9  = "(){return LBBx;}()) + c0(Dr) + (function fVCOm(){return RBsp;}()) + (function hOkWA(){return PAVP;}()) + SV(ArQb) + (function yr" ascii
    $s10 = "se;for (var irLt = 0; irLt < Vv() * 1; irLt++){if (u() != 0){o = true;ctRkX = true;break;}}function ydp() {return o && ctRkX;};i" ascii
    $s11 = " 10)};Uq = false;} catch(e){};}W = WScript[HQq()](hHY(M0) + N1 + (function y0(){return aW0;}()) + dD);W[(bgvf(Vvz))]();W[(functi" ascii
    $s12 = "r DpM = NKrj[\"charAt\"](4);var wN = \"Ru\";function xJbb(kVVE){return kVVE;};var vpYr = \"\\x6cl\";var x = \"e\";var ve = \".S" ascii
    $s13 = "arAt\"](2);var iBCH = \"MLHTT\";var tt = \"X\";var OSbc = \"L2.\";var ZG = \"MSXM\";function M(VD){return VD;};var NKrj = \"LK6W" ascii
    $s14 = "le\";var ilU = \"oF\";var LLOg = \"veT\";var pKU = \"Sa\";var jfez = \"n\";var D = \"\\x69\\x6f\";var wDLG = \"sit\";var yguNt =" ascii
    $s15 = "W1(bfqm){return bfqm;};var gw = \"3Spo\";var polD = \"dy\";var WSKj = gw[\"charAt\"](3);var gPL = \"nseB\";var wQWm = \"R\\x65" ascii
    $s16 = "5\";var Apo = Zq[\"charAt\"](1);function ycQa(jRdG){return jRdG;};function Aj(DXx){return DXx;};function K(vLUs){return vLUs;};f" ascii
    $s17 = "unction zEm(MD){return MD;};var R1 = \"rite\";var m0 = \"\\x77\";var pCV = \"oJe06Vt\";var I = pCV[\"charAt\"](2);var CEJ = \"t" ascii
    $s18 = "x6c\";var TK = \"e\\x74Mi\";var WGxa = \"g\";var Nz = \"ykt5Ozb\";var IO = \"e\";var czzm = Nz[\"charAt\"](2);var T = \"Da\";fun" ascii
    $s19 = "urn aS;};function L(meitB){return meitB;};function jUl(Grsm){return Grsm;};var A = \"i3DioeZeC\";var gt = A[\"charAt\"](5);var x" ascii
    $s20 = "var SHG = \"2c\";var xTHC = SHG[\"charAt\"](0);var ljvDn = \"3\\x3681\\x36\";var IAdnC = \"2\\x318\";function H(Vda){return Vda;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}