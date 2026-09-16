rule sig_20160321_7d46a95feb564c6ddf28fe853d0954ae {
  meta:
    description = "datamaliciousorder - file 20160321_7d46a95feb564c6ddf28fe853d0954ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d34a93107f3b4da9793e6529d2d6c99ef09cd40dae303b53c8b861a42e8e34"

  strings:
    $s1  = "function fcn(w0){return w0;};var aPpux = \"FaL2wR9R\";var zF = aPpux[\"charAt\"](3);var rnV = \"6\";var t = \"81\";var lnDg = \"" ascii
    $s2  = " bK;}()) + R + (function S(){return Z;}())]();WScript[U(kY) + (function G(){return TWFWp;}()) + (function Rqpj(){return ZNs;}())" ascii
    $s3  = "(){return mDZ;}()) + (function jP(){return k;}()), false);K[qN(s) + KX(qFd)]();while (K[f + e + P(zc) + PM(M0)] < 4 ) {WScript[n" ascii
    $s4  = "ph(){return RGZt;}()) + oRJ(GLwpy) + KekzB + (function U0(){return nrHn;}()); CN = kEiX(); K = WScript[Fevrr + excjJ(L) + zww(m)" ascii
    $s5  = "EhR(bK) + (function HsSXr(){return R;}()) + kkU(Z)]();WScript[(function OKNaT(){return kY;}()) + jc(TWFWp) + PA(ZNs) + (function" ascii
    $s6  = ") {return WScript[sgYmw(Fevrr) + L + oagDP(m) + (function tI(){return ScH;}())]((function PG(){return RhRW;}()) + Pxg(MdwaY) + E" ascii
    $s7  = "nction kEiX(){return (function Di(){return IOEqX;}()) + gDR + RqXmV + uduE(LHo);};function F(uyx, FHH){return uyx - FHH;};functi" ascii
    $s8  = "tion Pbf() {return zM && w;};if (Pbf()){vYnO = OGx[lT + BvIA(wShVw) + (function exSS(){return xuUB;}()) + cbnS(qxHj) + (function" ascii
    $s9  = "pjbV(kY) + EU(TWFWp) + (function HLXLi(){return ZNs;}()) + x](LQvn() * 10)};rXw = false;} catch(e){};}ZGB = WScript[ec()](lb(G1)" ascii
    $s10 = "qae = \"42eBA\";var pPQ = \"yop\";var x = pPQ[\"charAt\"](2);var ZNs = \"e\";var TWFWp = IPqae[\"charAt\"](2);var kY = \"S\\x6c" ascii
    $s11 = "Ic = IVL[\"charAt\"](2);function lb(NhzxU){return NhzxU;};function H(L1){return L1;};var xV = \"IUceIGHS6\";var jlddh = \"am\";v" ascii
    $s12 = "){return R0;};var Z = \"s\";var R = \"\\x6fn\\x64\";var bK = \"\\x65c\";var i = \"llis\";var yO = \"getM\\x69\";function mHxS(sK" ascii
    $s13 = "ar NeJXz = \"RadN3Ak\";var qFd = NeJXz[\"charAt\"](2);var s = \"s\\x65n\";function xduG(qO){return qO;};function tu(XT){return X" ascii
    $s14 = "XWN[\"charAt\"](4);var mHoE = \"C\\x72ea\\x74\";function uduE(cq){return cq;};var LHo = \"\\x54TP\";var RqXmV = \"\\x58MLH\";var" ascii
    $s15 = "\"charAt\"](3);function VhPET(y){return y;};var xn = \"P\\x25\\x2f\";var POvx = \"%TEM\";function BvIA(R1){return R1;};function " ascii
    $s16 = "= xV[\"charAt\"](3);var rbvK = \"B\\x2eStr\";var G1 = \"\\x41DOD\";var DQL = \"Sleep\";function P(sbM){return sbM;};function PM(" ascii
    $s17 = "ction UDf(vfLWR){return vfLWR;};var FSdi = \"vPGkd6\";var k = \"s\";var mDZ = FSdi[\"charAt\"](0);var TeP = \"j49\";var Xr = \"/" ascii
    $s18 = "L[\"charAt\"](0);var R2 = \"ate\";var mo = \"\\x43r\\x65\";function trVQ(Bokr){return Bokr;};function oRJ(Pmoo){return Pmoo;};va" ascii
    $s19 = "function fcn(w0){return w0;};var aPpux = \"FaL2wR9R\";var zF = aPpux[\"charAt\"](3);var rnV = \"6\";var t = \"81\";var lnDg = \"" ascii
    $s20 = "function cRdvO(){return QeBU;}())](vYnO, 2 );ZGB[(function bR(){return ENA;}()) + v0(lnlRr) + b0(HiAuU)]();eqNC(vYnO);GJ = \"\" " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}