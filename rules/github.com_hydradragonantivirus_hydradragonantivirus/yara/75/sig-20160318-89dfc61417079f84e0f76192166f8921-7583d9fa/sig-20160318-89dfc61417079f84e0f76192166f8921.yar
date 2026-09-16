rule sig_20160318_89dfc61417079f84e0f76192166f8921 {
  meta:
    description = "datamaliciousorder - file 20160318_89dfc61417079f84e0f76192166f8921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7357ec9883af3dac63f8d0bf2d5fa48e08ae97a9b8b2bde1be28154d0943048"

  strings:
    $s1  = "var EDgaX = \"i\\x6e\\x21\";var sswAW = \"a\";var QXSd = \"ag\";var S1 = \"y \";var V0 = \"e\\x2c t\\x72\";var J0 = \"s\";var m " ascii
    $s2  = "(function Z0(){return Xmq;}()) + (function fRBg(){return mpZsQ;}())] < 4 ) {WScript[(function NE(){return Q;}()) + (Tcw)](jf() *" ascii
    $s3  = "()) + (function f(){return heZ;}()) + (VP) + (EdtSS) + (function wkTVO(){return r;}()) + (Y0); ooK = UWCMo(); ng = WScript[(func" ascii
    $s4  = "eturn X;}()) + (function EfV(){return bp;}());}else{WScript.Echo((function xv(){return bBA;}()) + (m) + (function BDd(){return J" ascii
    $s5  = "tion w0(){return uZN;}()) + (aCbIo) + (function sJ(){return tZn;}())]();WScript[(function puLh(){return Q;}()) + (function T(){r" ascii
    $s6  = " 10)};dPBeT = WScript[pshJw()]((function NjbyB(){return ef;}()) + (function qS(){return uqoj;}()) + (function T0(){return sUM;}(" ascii
    $s7  = "rn aCbIo;}()) + (function SGD(){return tZn;}())]();WScript[(function bAMKo(){return Q;}()) + (Tcw)](jf());var XEL = new this[(fu" ascii
    $s8  = "2e\\x61\";var S = function YBV() {return WScript[(function WGx(){return szth;}()) + (function qIQY(){return xc;}()) + (function " ascii
    $s9  = "tion qKE(QMACD, Ae){return QMACD - Ae;};function pshJw(){return (szth) + (function tw(){return xc;}()) + (w) + (l);};function jf" ascii
    $s10 = " 0; Nu < jf() * 1; Nu++){if (W() != 0){tSds = true;GA = true;break;}}function ErpD() {return tSds && GA;};if (ErpD()){ogc = S[(f" ascii
    $s11 = " heNxk;}()) + (function D0(){return eI;}()) + (function KgLUi(){return fmdP;}()) + (Ied), false);ng[(function TZ(){return uxNeg;" ascii
    $s12 = "(){return (function aQbd(){return XYXgr;}()) + (SiI) + (function EH(){return thrrq;}()) + (function wChvn(){return h;}());};func" ascii
    $s13 = "EL[(function Xe(){return Ki;}()) + (function FE(){return STUUR;}()) + (function bEYmj(){return uZN;}()) + (function qeBcg(){retu" ascii
    $s14 = "n pQmc;}()) + (function nfSFq(){return q0;}()) + (dQJ)]((function mYlTz(){return y;}()) + (function tNjwE(){return SfV;}()) + (f" ascii
    $s15 = "nction v(){return SFkn;}()) + (function TnjL(){return sxN;}())]();var H = XEL[(Ki) + (function JdFEc(){return STUUR;}()) + (func" ascii
    $s16 = "}()) + (function KXaq(){return V;}()) + (wZCY) + (function z0(){return MKZVO;}()) + (function H0(){return mGyE;}()) + (function " ascii
    $s17 = ")) + (function d(){return rIe;}()));dPBeT[((function UCM(){return atMg;}()) + (function Yb(){return A0;}()))]();dPBeT[(FbbM)] = " ascii
    $s18 = "n dl;}()) + (Kyau)](ogc, 2 );dPBeT[(lxyo) + (function EIoVu(){return Upn;}())]();Z(ogc);xanBu = \"\" + (function T1(){return aAd" ascii
    $s19 = "? (function yDLPg(){return s;}()) + (function VMw(){return Pcfto;}()) : (oCLGg) + (function k(){return Yv;}()) + (function u(){r" ascii
    $s20 = " (function hoqnj(){return pNX;}()) + (function Y(){return bJtS;}()));}();function Z(QQejm){S[(al)](QQejm, 0, 0);};function UWCMo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}