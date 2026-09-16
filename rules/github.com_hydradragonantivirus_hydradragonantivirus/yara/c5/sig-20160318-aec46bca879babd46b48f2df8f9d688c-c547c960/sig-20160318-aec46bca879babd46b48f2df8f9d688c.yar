rule sig_20160318_aec46bca879babd46b48f2df8f9d688c {
  meta:
    description = "datamaliciousorder - file 20160318_aec46bca879babd46b48f2df8f9d688c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3925a5dd854aedd49d7be1694a44c243fd8a522ce0cc1829a4d8b82a0fa4bf"

  strings:
    $s1  = "var yrxv = \"\\x6e\\x21\";var UnvZK = \"gai\";var qpYj = \"\\x74ry \\x61\";var J0 = \"sMu rZ\"[\"charAt\"](3);var hb = \"se,\";v" ascii
    $s2  = "(){return oqXG;}()) + (function eW(){return gVU;}());}else{WScript.Echo((function bl(){return WBHQ;}()) + (function oGQ(){return" ascii
    $s3  = "on Fvp(){return p;}()) + (function Pso(){return QEV;}()) + (gjiL)]();WScript[(function whn(){return aUaRs;}()) + (function aJOYQ" ascii
    $s4  = "+ (function Xc(){return uk;}()) + (function ak(){return zi;}()) + (p) + (function K0(){return QEV;}()) + (gjiL)]();WScript[(func" ascii
    $s5  = "QIs;}()) + (function SzLBD(){return FxoY;}()) + (function LYrq(){return yVFG;}())] < 4 ) {WScript[(aUaRs) + (function p0(){retur" ascii
    $s6  = " fo() {return WScript[(function OrDM(){return FZakE;}()) + (function gpYok(){return k;}()) + (function w(){return rK;}()) + (fun" ascii
    $s7  = "n d;}()) + (function fYnd(){return rS;}())](I() * 10)};pjiXZ = WScript[Iw()]((udUsF) + (xfmSd) + (function Nm(){return ag;}()) +" ascii
    $s8  = " Pw = ol(); KbKT = WScript[(FZakE) + (function PO(){return k;}()) + (function jTw(){return rK;}()) + (function dsN(){return oJlP" ascii
    $s9  = "eturn V;}()) + (function sdq(){return VJclf;}());};function lUf(cdWl, B){return cdWl - B;};function Iw(){return (function ChGH()" ascii
    $s10 = "H = true;break;}}function uD() {return oWIk && KBH;};if (uD()){yG = DmwG[(function s0(){return KW;}()) + (function jw(){return W" ascii
    $s11 = "charAt\"](5);var UF = \"W\\x53cr\";var R = \"ct\";var oJlP = \"e\";var rK = \"eObj\";var k = \"\\x74\";var FZakE = \"Crea\";var " ascii
    $s12 = "r Fn = \"5i6C\"[\"charAt\"](1);var UFC = \"ToF\";var Qa = \"Save\";var rEsP = \"on\";var q = \"os\\x69ti\";var Om = \"qdPApAbi\"" ascii
    $s13 = "return lUf(vVE, OYvz);}var oWIk = false;var KBH = false;for (var DwS = 0; DwS < I() * 1; DwS++){if (TEAhX() != 0){oWIk = true;KB" ascii
    $s14 = "TP;}()) + (function MI(){return q0;}()) + (function CiY(){return C0;}()) : (Pg) + (function G(){return VmYCR;}()) + (function h1" ascii
    $s15 = ")) + (Bf) + (function KyhG(){return qTd;}()) + (OTDQ) + (function jClcy(){return NW;}()) + (INNb) + (function hJcvn(){return t;}" ascii
    $s16 = " (function xJ(){return WwKG;}()) + (function b(){return izvOb;}()));pjiXZ[((h) + (jszl))]();pjiXZ[(function lQ(){return O;}()) +" ascii
    $s17 = "n k2(){return Fn;}()) + (hPXv) + (sa)](yG, 2 );pjiXZ[(NAV) + (function Ci(){return rLgcH;}())]();eTt(yG);vVE = \"\" + (function " ascii
    $s18 = "(){return QEV;}()) + (function ZMHI(){return gjiL;}())]();var vVE = \"HCXCg\";vVE = lUf(F, wh);var OYvz = \"IFRu\";OYvz = lUf(s," ascii
    $s19 = " + (q) + (function OC(){return rEsP;}())] = 0;pjiXZ[(function CZ(){return Qa;}()) + (function qPWvN(){return UFC;}()) + (functio" ascii
    $s20 = "unction CYHD(){return ipP;}()) + (function KT(){return l;}()) + (function k1(){return irA;}()) + (function tvJ(){return nI;}());" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}