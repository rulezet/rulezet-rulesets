rule sig_20160318_0a8081475f7f1ac6e2d2021dde717af2 {
  meta:
    description = "datamaliciousorder - file 20160318_0a8081475f7f1ac6e2d2021dde717af2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7d5a174dbd35d1805119f99be526cc633c4f23eed667b0874f0b10de23a168f"

  strings:
    $x1  = "var u0 = \"!\";var KKjP = \"aga\\x69n\";var araJM = \"yb g\"[\"charAt\"](2);var XCYp = \"ry\";var C = \" t\";var DSfp = \"e,\";v" ascii
    $s2  = "n QzIwE;}()) + (function XQm(){return e0;}()) + (CI) + (function B(){return b;}()) + (jL); BH = e(); Lph = WScript[(function nJE" ascii
    $s3  = " XZ;}()) + (function hgxDT(){return VqiNW;}()) + (function qo(){return xkBDD;}())] < 4 ) {WScript[(function HASaT(){return dMA;}" ascii
    $s4  = "()) + (function HkQ(){return UwJ;}())](o() * 10)};sCvI = WScript[ru()]((function Cqq(){return c;}()) + (lzSD) + (function MoB(){" ascii
    $s5  = "qf) + (function NNfW(){return Bz;}())]();WScript[(function K(){return dMA;}()) + (function BKJou(){return UwJ;}())](o());var V =" ascii
    $s6  = "A;}()) + (function xtU(){return Voqf;}()) + (function TQZ(){return Bz;}())]();WScript[(function Exv(){return dMA;}()) + (UwJ)](o" ascii
    $s7  = " + (nH) + (function CM(){return UX;}()) + (function xKhF(){return JQrCQ;}());};function NV(klz, zogha){return klz - zogha;};func" ascii
    $s8  = "cript.Echo((function IoLgK(){return GMRk;}()) + (function wtFGs(){return vY;}()) + (function aIo(){return DSfp;}()) + (function " ascii
    $s9  = "var MUUF = \"\\x63\\x74\";var l = \"\\x65Ob\\x6ae\";var w = \"\\x74\";var k = \"\\x43rea\";var V0 = function NYr() {return WScri" ascii
    $s10 = " ypv(){return vcG;}()) + (function CFmg(){return bQ;}()) + (function rio(){return s;}()) + (jIcW)]((function y(){return CoBa;}()" ascii
    $s11 = "(){return k;}()) + (function TIA(){return w;}()) + (function TS(){return l;}()) + (function V1(){return MUUF;}())]((function xIT" ascii
    $s12 = "());var V = new this[(function Ohft(){return ExNND;}())]();var WBO = V[(function ngRp(){return P;}()) + (function sG(){return qu" ascii
    $s13 = "0[(function U(){return Tcv;}())](eQ, 0, 0);};function e(){return (function mtD(){return IFFMR;}()) + (function E(){return W;}())" ascii
    $s14 = "{return WcVc;}()) + (function X0(){return Qz;}()) : (function aPM(){return rOHF;}()) + (function WE(){return lBosE;}());}else{WS" ascii
    $s15 = "function pe(){return Yub;}()) + (function gG(){return zjB;}()), false);Lph[(nETpY)]();while (Lph[(fStDa) + (function Ku(){return" ascii
    $s16 = "] = 0;sCvI[(JMXqB) + (Cr) + (U0) + (function Ko(){return PVX;}())](vmDoW, 2 );sCvI[(cIe) + (function xmUD(){return bl;}()) + (fu" ascii
    $s17 = " new this[(ExNND)]();var ZDYYu = V[(function MhAr(){return P;}()) + (function n0(){return quF;}()) + (function RYM(){return ZHSz" ascii
    $s18 = "RE(){return rlO;}()) + (function rO(){return tYJ;}()) + (g) + (jND) + (function OH(){return ZmGMm;}()));}();function BDNEG(eQ){V" ascii
    $s19 = "QZt(){return QwEQ;}())](Lph[(function FUY(){return u;}()) + (function DZsC(){return Vkz;}()) + (function LxibX(){return P0;}()) " ascii
    $s20 = "(){return ZoWW;}()) + (RZxo) + (function fQZn(){return Pgcd;}()) + (oLt) + (function g1(){return g0;}()) + (function s0(){return" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}