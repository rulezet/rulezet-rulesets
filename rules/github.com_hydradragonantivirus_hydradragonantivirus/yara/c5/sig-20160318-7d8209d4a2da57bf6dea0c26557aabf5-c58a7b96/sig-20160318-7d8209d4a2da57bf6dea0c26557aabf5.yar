rule sig_20160318_7d8209d4a2da57bf6dea0c26557aabf5 {
  meta:
    description = "datamaliciousorder - file 20160318_7d8209d4a2da57bf6dea0c26557aabf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c3495e2aeac659e19b6e37f5392a6b4a181e84e0fcb8a94c8d09738f4cd6f57"

  strings:
    $s1  = "var anaYq = \"\\x61in\\x21\";var M = \"\\x79 \\x61\\x67\";var jlqB = \"\\x20tr\";var v = \"mjEp,Mc7\"[\"charAt\"](4);var fYNp = " ascii
    $s2  = "* 10)};gH = WScript[yfbb()]((eUY) + (function RW(){return LYIZ;}()) + (function FlT(){return AwNu;}()) + (function eP(){return E" ascii
    $s3  = "sK)]();while (rTJ[(function Z(){return e0;}()) + (function C1(){return T0;}()) + (IdQG)] < 4 ) {WScript[(nONj) + (HpjrC)](LWR() " ascii
    $s4  = "eturn mGWW;}()) + (function B1(){return ab;}()) + (function I(){return RDKz;}());}else{WScript.Echo((z0) + (function UwQmL(){ret" ascii
    $s5  = ") + (Rub) + (function i(){return YzOu;}()) + (function EgrxV(){return xfRt;}())]();WScript[(nONj) + (function Pv(){return HpjrC;" ascii
    $s6  = ";}())]();WScript[(function ibacu(){return nONj;}()) + (function lOX(){return HpjrC;}())](LWR());var hT = new this[(function T(){" ascii
    $s7  = "qpq() {return WScript[(function Zl(){return rL;}()) + (r) + (XJ) + (function AyxV(){return lkCdk;}())]((function nXuWW(){return " ascii
    $s8  = " (function ottFi(){return r1;}());};function Mmy(Dg, n){return Dg - n;};function yfbb(){return (function qiE(){return rL;}()) + " ascii
    $s9  = "var dweIB = \"WSc\";var lkCdk = \"qW74trR\"[\"charAt\"](4);var XJ = \"\\x4fbjec\";var r = \"te\";var rL = \"Cr\\x65\\x61\";var m" ascii
    $s10 = "oP(){return qZz;}()) + (function XYhXD(){return eJNx;}()) + (cO) + (function QEw(){return ev;}()) : (rcjB) + (function UvEbM(){r" ascii
    $s11 = " AD(){return mGoSP;}()) + (zLbDd) + (function uxAA(){return XKB;}()) + (c0) + (function VbCd(){return In;}()) + u ? (function cI" ascii
    $s12 = "ction wHrTD(){return URmSJ;}()) + (function Ft(){return Rub;}()) + (function PbeC(){return YzOu;}()) + (function x(){return xfRt" ascii
    $s13 = "cript[(function QO(){return rL;}()) + (r) + (function oztT(){return XJ;}()) + (function qlL(){return lkCdk;}())](Lt);rTJ[(functi" ascii
    $s14 = "}())](LWR());var hT = new this[(function ZJa(){return wu;}()) + (function sbtO(){return t;}())]();var si = hT[(AMvX) + (function" ascii
    $s15 = ") + (xNa) + (function sK(){return b0;}()) + (function n1(){return y;}()) + (function OKvL(){return frH;}()) + (mqAF) + (function" ascii
    $s16 = "unction xv(){return LL;}()) + (KNU) + (p) + (function n0(){return JU;}())]);gH[(function JKjia(){return RLLkl;}()) + (function Q" ascii
    $s17 = "dtJ(){return VUkcO;}()) + (function Zas(){return d0;}()) + (function r2(){return QM;}()) + (function zAdw(){return NBXW;}())]((f" ascii
    $s18 = "rn tqXpl;}()) + (function Jv(){return QXYL;}()) + (function s(){return BRI;}()) + (function nbnbG(){return P;}()), false);rTJ[(d" ascii
    $s19 = "e(){return iXz;}()) + (TBhW)] = 0;gH[(GBp) + (e1) + (vU)](nr, 2 );gH[(function eO(){return guBgZ;}())]();AxrBy(nr);yT = \"\" + (" ascii
    $s20 = "my(Y, aczk);var crg = \"f\";crg = Mmy(si, Y);return Mmy(yT, crg);}var u = false;var ZK = false;for (var LYk = 0; LYk < LWR() * 1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}