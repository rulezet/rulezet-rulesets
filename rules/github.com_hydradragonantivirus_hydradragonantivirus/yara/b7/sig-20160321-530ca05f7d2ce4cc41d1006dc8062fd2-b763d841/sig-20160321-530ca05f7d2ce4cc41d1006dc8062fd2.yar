rule sig_20160321_530ca05f7d2ce4cc41d1006dc8062fd2 {
  meta:
    description = "datamaliciousorder - file 20160321_530ca05f7d2ce4cc41d1006dc8062fd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f0d20767b911c24f2374a47e0508294c324d65016ee0cffee841aa4803fbf4b"

  strings:
    $s1  = "function BL(Ypnp){return Ypnp;};function UMt(YZp){return YZp;};var rCE = \"\\x36\\x381\\x36\\x32\";var as = \"\\x3218\\x33\";var" ascii
    $s2  = "return gFJh;}()) + BjR]();WScript[(function GM(){return hfX;}())](n());var D = new this[SmG]();var ER = D[QuXQ + c(pRt) + rJiQq(" ascii
    $s3  = "ion hptsU(){return DPqtX;}()) + (function ZQt(){return hRlfm;}()); Lie = CxOHK(); xSNdA = WScript[gnN + (function LpNq(){return " ascii
    $s4  = "E = \"ate\";var gnN = \"Cr\\x65\";var hK = function CT() {return WScript[xbK(gnN) + XE + jNuI + lNzI + (function HwN(){return pp" ascii
    $s5  = "urn QuXQ;}()) + pRt + rPHx(j) + (function EMJxw(){return gFJh;}()) + (function dsyzm(){return BjR;}())]();WScript[(function CBNE" ascii
    $s6  = "U1]();while (xSNdA[(function cG(){return JlAK;}()) + n0(GQxH) + (function YLx(){return dEgRr;}()) + Xo(otO)] < 4 ) {WScript[(fun" ascii
    $s7  = "rn mqs - uzQ;};function fvFx(){return UN(gnN) + (function K(){return XE;}()) + (function by(){return jNuI;}()) + HXkR(lNzI) + pp" ascii
    $s8  = "ction B(){return hfX;}())](n() * 10)};XLeY = false;} catch(e){};}cM = WScript[fvFx()](h(yZZXS) + (function xYpt(){return jKcr;}(" ascii
    $s9  = "54\\x6f\";var PuxEh = \"\\x76e\";var NQi = nwVEW[\"ch\\x61rAt\"](0);var G2 = D2[\"ch\\x61rAt\"](3);function FO(Vhhu){return Vhhu" ascii
    $s10 = ";var hzTKR = kH[\"ch\\x61rAt\"](1);var mdi = \"s\\x64\";var ZGGw = \"asdfa\";function R0(oqovh){return oqovh;};function ZhG(zdbn" ascii
    $s11 = "var Am = Ev[\"ch\\x61rAt\"](1);var krf = \"\\x6e\";var EF = \"ope\";function h(Bg){return Bg;};function frWUi(Z0){return Z0;};va" ascii
    $s12 = "\"SXML\";var Ka = u[\"ch\\x61rAt\"](1);function DsD(P){return P;};var aRZ = \"\\x52un\";function ZGO(JZE){return JZE;};var mL = " ascii
    $s13 = "KL7\";var GrI = J[\"ch\\x61rAt\"](3);var yt = \"Da\\x74\";var hfX = \"Sle\\x65p\";function rPHx(du0){return du0;};function gaJYM" ascii
    $s14 = "r v0 = \"VUeAehI9KL\";var IEa = v0[\"ch\\x61rAt\"](4);var YGRC = \"os\";var gtBx = \"cl\";function EXndI(iemfr){return iemfr;};f" ascii
    $s15 = "urn COyZ;};function c(BlKS){return BlKS;};function rJiQq(Kuz){return Kuz;};var DxCB = \"1d8sXZ\";var BjR = DxCB[\"ch\\x61rAt\"](" ascii
    $s16 = "turn yzXc;};function ba(sM){return sM;};var xzE = \"QOy5\";var ppc = \"ct\";var lNzI = \"\\x62je\";var jNuI = xzE[\"ch\\x61rAt\"" ascii
    $s17 = "var R = \"sd\\x66a\";var rC = P0[\"ch\\x61rAt\"](1);var cJtv = \"j\\x61\";var yMoJ = \"dlfk\";var ZOvq = \"as\";function Ckl(m){" ascii
    $s18 = "RGub\";IKtiq = xfD(ER, CYNb);return xfD(saHr, IKtiq);}var PQnzb = false;var L = false;for (var SQ = 0; SQ < n() * 1; SQ++){if (h" ascii
    $s19 = "nction YkbS(){return MzBz;}()) + CRFuy + yUZM(Z) + (function dp(){return ockob;}()) + (function GYZW(){return ADQQ;}()) + (funct" ascii
    $s20 = ");};function CxOHK(){return (function fCB(){return Ka;}()) + (function Xj(){return XWYg;}()) + (function mW(){return avpJD;}()) " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}