rule sig_20160321_b14489f113e050ae21c5c29eb1ff62fb {
  meta:
    description = "datamaliciousorder - file 20160321_b14489f113e050ae21c5c29eb1ff62fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fb0bde5508e37267c4f7eb40b896d6e95e5993f451b65f0de42f175c6ed9746"

  strings:
    $s1  = "var Yl = \"162\";var AH = \"68\";var x = \"2\\x3183\";function c0(I0){return I0;};var Td = \"OVsrrEK\";var U3 = \"d\";var HQH = " ascii
    $s2  = " eL = fzWz[\"charAt\"](3);var oeLUA = \"TEMP%\";var q0 = B[\"charAt\"](2);function OHdZc(sodMl){return sodMl;};function iaJN(aVN" ascii
    $s3  = "* 1; oWvY++){if (xCKut() != 0){BoM = true;wzC = true;break;}}function Wi() {return BoM && wzC;};if (Wi()){xfl = U[OHdZc(mLxHU) +" ascii
    $s4  = "L)) + pWtbj(z0) + (function jRx(){return tn;}()) + kFAQ + Knc(yZK); ps = wYg(); X = WScript[Zcw(gfLWG) + BUQL(he) + ejL + (funct" ascii
    $s5  = "Udrga() {return WScript[(function TS(){return gfLWG;}()) + (function vBAHh(){return he;}()) + ejL + (function l(){return V;}())]" ascii
    $s6  = "uvBI;}()) + (function h(){return y;}()) + YQEWd + (function FupY(){return xTA;}()) + (function D(){return Xvb;}())]();WScript[jE" ascii
    $s7  = "){return ZU;}()) + UdG(GuvBI) + y + M(YQEWd) + gsK(xTA) + Xvb]();WScript[iLSi + (function QSBK(){return GdGFM;}())](z());var rC " ascii
    $s8  = " mF;}());};function ZwJD(mpXo, UyAOy){return mpXo - UyAOy;};function bMc(){return (function fDGF(){return gfLWG;}()) + ojWO(he) " ascii
    $s9  = "cript[D0(iLSi) + (function uLNUk(){return GdGFM;}())](z() * 10)};GKJT = false;} catch(e){};}Mlr = WScript[bMc()]((function tFvo(" ascii
    $s10 = "\"a\\x73dlf\";function ChMs(MM){return MM;};function uA(TH){return TH;};var xFr = \"XssTh\";var S2 = \"e\";var gpwrv = xFr[\"cha" ascii
    $s11 = "= \"\\x70o\\x73i\";function TdR(t2){return t2;};var Ky = \"y\";var dmrRB = Ky[\"charAt\"](0);var DGCF = \"eBod\";var uz = \"\\x6" ascii
    $s12 = "n bEhg(S0){return S0;};function E0(P0){return P0;};var U2 = \"xitFXbYY\";var VForJ = \"zcfmzcb6y\";var PcOn = VForJ[\"charAt\"](" ascii
    $s13 = "= U3[\"charAt\"](0);var p = Td[\"charAt\"](2);var KNN = \"fa\";var Dpo = \"\\x61sd\";function T3(wX){return wX;};function B0(nw)" ascii
    $s14 = "arAt\"](2);var aeBUg = \"S\";function JHY(FVViH){return FVViH;};var fU = \"t\\x61te\";var KkFc = \"ad\\x79s\";var cwE = \"\\x72e" ascii
    $s15 = "harAt\"](1);var wU = \"t\";var t1 = \"c\";var TfZz = \"\\x4fbje\";var O = \"ate\";var ocVc = \"e\";var rps = \"\\x43r\";function" ascii
    $s16 = "unction EBM(){return y;}()) + rOU(YQEWd) + xTA + (function XGAs(){return Xvb;}())]();var yIB = \"osscn\";yIB = ZwJD(ObzsA, gx);v" ascii
    $s17 = " = \"\" + VsEFU + T3(c) + CWq + NZyOb + (function Rg(){return T2;}()) + (function JMtK(){return irq;}()) + OPC + (function rx(){" ascii
    $s18 = " Vr + F + iaJN(k) + (function brto(){return oY;}()) + TaO + L + (function h0(){return Gj;}()) + C(A)](gX(q0) + jvo(oeLUA) + Kr(e" ascii
    $s19 = "+ wSg(ejL) + VAEQ(V);};function z(){return 22;};function xCKut(){var rC = new this[Hkxh(eZuFK) + eI]();var gx = rC[(function y0(" ascii
    $s20 = "= new this[(function De(){return eZuFK;}()) + (function AFDbP(){return eI;}())]();var ObzsA = rC[ZU + (function BFOEq(){return G" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}