rule sig_20160321_90b8d8cd6824784b2d24d31ef9918348 {
  meta:
    description = "datamaliciousorder - file 20160321_90b8d8cd6824784b2d24d31ef9918348.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f761161cfee568bd809871ff8fc01fdbf09187f9c81b1d0f3c8396070ba061b3"

  strings:
    $s1  = "function Bi(O2){return O2;};var QcoQ = \"JSwsj2Ne\";var Gl = \"1\\x362\";var Ul = \"\\x318368\";var wmpg = QcoQ[\"ch\\x61\\x72At" ascii
    $s2  = " + R1 + P0]();WScript[(function xUMM(){return HAjZ;}()) + (function O1(){return WC;}()) + (function CEdW(){return QX;}())](V());" ascii
    $s3  = " (function rDj(){return tn;}()); uIYoG = VjpW(); IT = WScript[VsSq(dB) + (function xTS(){return MZ;}()) + (function uvXD(){retur" ascii
    $s4  = "N;}()) + (function zG(){return UJurl;}()) + (function Hm(){return R1;}()) + (function VwR(){return P0;}())]();WScript[(function " ascii
    $s5  = "h(e){};}skt = WScript[eg()]((function P1(){return mvNY;}()) + oV + (function avpJV(){return mx;}()) + TU + Oj(gCy));skt[((functi" ascii
    $s6  = " (function RtSW(){return a;}()) + (function m0(){return tQx;}()) + HwqI(D);};function d(PS, Lgv){return PS - Lgv;};function eg()" ascii
    $s7  = "r MZ = \"e\";var dB = \"Cr\";var CAxL = function BLSX() {return WScript[(function dYu(){return dB;}()) + (function ZRfhb(){retur" ascii
    $s8  = " T;}())] < 4 ) {WScript[(function dKUii(){return HAjZ;}()) + (function xHPnq(){return WC;}()) + QX](V() * 10)};yq = false;} catc" ascii
    $s9  = "wmpg + Bi(Ul) + (function kqpq(){return Gl;}());}" fullword ascii
    $s10 = "var SYM = \"xWMl\";SYM = d(jKrXI, kPBY);return d(zNPbW, SYM);}var R0 = false;var nQFlz = false;for (var g = 0; g < V() * 1; g++)" ascii
    $s11 = " + CWxwH(YW) + (function tJVd(){return UtFN;}()) + RpjYf + (function IpP(){return D0;}()) + Om(yyXjI) + tUUm + Q](jNGp + ZZXy(tF" ascii
    $s12 = "Ad(DwWf) + (function aE(){return hhGcI;}()) + zkc(p) + uwFD(QaaM) + vo(zE) + YUGoJ + ul(kS) + (function e(){return Vb;}()) + fon" ascii
    $s13 = "n UuEEv;}()) + (function HK(){return qLGH;}()) + yiir(P) + Lx](uIYoG); var yq = true; while (yq){try {IT[(function L(){return hE" ascii
    $s14 = "rn vpl;}()) + LJR + ALOzi(vWiu) + (function H(){return bfoIO;}()) + (function cI(){return aqJd;}()) + (function dvG(){return XwP" ascii
    $s15 = "on edNNN(){return TNxBf;}()) + UUyN(yDm)]);skt[(function hvc(){return SogQK;}()) + (function RU(){return SFJhi;}())] = 0;skt[ShG" ascii
    $s16 = ";}()) + (function XkM(){return UuEEv;}()) + gQbFV(qLGH) + P + nhWLL(Lx)]((function YqO(){return IGK;}()) + Hhwi(IitEt) + q(VNVwp" ascii
    $s17 = "r;}())](w(wXMn), F(XDyu) + Xuihs + (function Iaiq(){return HAi;}()) + nBw(bKJR) + pik(xTan) + (function fob(){return nFf;}()) + " ascii
    $s18 = "on StAn(){return hEr;}()))]();skt[vqE(a1)] = 1;skt[Cq + E(NxXb)](IT[(function a2(){return YynUI;}()) + YDA(oVp) + IQJd + (functi" ascii
    $s19 = "yT(rk) + kVIj(GEG) + pYQbL(dVDvt), false);IT[(function Lfnq(){return dIrX;}()) + x0(Um)]();while (IT[AsO + (function W0(){return" ascii
    $s20 = "ar kPBY = GJC[vpl + LJR + LvEWZ(vWiu) + (function udcjY(){return bfoIO;}()) + aqJd + (function RhA(){return XwPN;}()) + G(UJurl)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}