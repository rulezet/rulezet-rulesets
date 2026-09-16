rule sig_20160321_a76515cfae60115111a00d991d7fa5bc {
  meta:
    description = "datamaliciousorder - file 20160321_a76515cfae60115111a00d991d7fa5bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35e68a63ffaa77988fdfcbc2ddfb05969c08086650aee7670a26e8547e18d702"

  strings:
    $x1  = "var bbnX = \"6\\x32\";var NXs = \"3\\x3681\";var qMwzs = \"218\";function A2(oxSs){return oxSs;};function dQlNS(B0){return B0;};" ascii
    $s2  = "Q = \"r\\x65a\";var QhJ = \"C\";var rvrKE = function POmpY() {return WScript[(function z(){return QhJ;}()) + Xcw(Q) + (function " ascii
    $s3  = "eturn U;}()) + m(MUgEJ) + (function piGK(){return bpXF;}()) + (function A(){return zAvWo;}()) + KLWz(RaU) + n0(xVTPa)]();WScript" ascii
    $s4  = " xVTPa]();WScript[Mc + FwTci(Z0)](MkTrx());var SMMPF = new this[LBK + (function DIG(){return EdfB;}())]();var Cq = SMMPF[r(U) + " ascii
    $s5  = "iMnO;}()) + (function Vkpf(){return dXxU;}()); Uv = sVu(); VW = WScript[QhJ + Q + eSyTd(Al) + W + s0(O) + (function dPRRr(){retu" ascii
    $s6  = " JgQT + a + (function bNhWc(){return RIECD;}());};function aIEp(HtrG, Y){return HtrG - Y;};function DVLdD(){return (function eap" ascii
    $s7  = " = true;d = true;break;}}function kQaR() {return ayE && d;};if (kQaR()){ecO = rvrKE[yk(h) + JSp(C0) + (function HmoFp(){return u" ascii
    $s8  = "[(function NRn(){return Mc;}()) + Zw(Z0)](MkTrx());var SMMPF = new this[(function qnbkr(){return LBK;}()) + (function CoZ(){retu" ascii
    $s9  = ") {WScript[Yh(Mc) + (function H(){return Z0;}())](MkTrx() * 10)};hA = false;} catch(e){};}i = WScript[DVLdD()](VJfnJ(E1) + q(B) " ascii
    $s10 = " \"furP\";var HCP = d0[\"c\\x68arAt\"](0);var niF = \"dfa\\x73\\x64\";var J = \"as\";function AcLW(DMc){return DMc;};function DO" ascii
    $s11 = "7et\";var SpI = \"rftY\";var P = \"e\";var fVZX = SpI[\"c\\x68arAt\"](2);var kJRnc = \"Da\";function Zw(t0){return t0;};function" ascii
    $s12 = "73dl\";var tfCsC = \"\\x63lose\";function VK(S){return S;};var PUiPU = \"aegx\";var V0 = PUiPU[\"c\\x68arAt\"](1);var I0 = \"\\x" ascii
    $s13 = "n s0(Fi){return Fi;};var rKg = \"rM4tkKfp\";var lagiN = \"t\";var O = \"\\x4fb\\x6a\\x65c\";var W = \"e\";var Al = rKg[\"c\\x68a" ascii
    $s14 = "eturn mQvv;};function Fr(E){return E;};function isYbO(gycu){return gycu;};var jux = \"0J5GgsE20Z6\";var xVTPa = jux[\"c\\x68arAt" ascii
    $s15 = "return SbmTl;};var KsX = \"Hfd4CE\";var sn = KsX[\"c\\x68arAt\"](1);var l1 = \"is\\x64\";var NsdNX = \"uh\";var sQk = \"dfya\";v" ascii
    $s16 = "oeX(IJit){return IJit;};function X(iWdD){return iWdD;};var sFx = \"4PlJO\";var RIECD = sFx[\"c\\x68arAt\"](1);var a = \"LHT\\x54" ascii
    $s17 = "turn yfDm;};var I = \"tg1Zd\";var KElaR = \"t\\x61te\";var TvKiz = \"ys\";var CUHOJ = I[\"c\\x68arAt\"](4);var Jsmy = \"rea\";fu" ascii
    $s18 = ";}()) + MXo(qMNe) + lho + Cqlz(c) + uo(Hc) + (function X0(){return wPyD;}())](Nt + (function fZqEl(){return LgUw;}()) + K + (fun" ascii
    $s19 = "eturn Al;}()) + Lmwm(W) + IVUJ(O) + (function n(){return lagiN;}())](jO + wvYWY(W0) + ExZNx(QHm) + RqI);}();function XC(ziF){rvr" ascii
    $s20 = "= aIEp(Cq, SJ);return aIEp(l, f);}var ayE = false;var d = false;for (var Ahbv = 0; Ahbv < MkTrx() * 1; Ahbv++){if (M() != 0){ayE" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}