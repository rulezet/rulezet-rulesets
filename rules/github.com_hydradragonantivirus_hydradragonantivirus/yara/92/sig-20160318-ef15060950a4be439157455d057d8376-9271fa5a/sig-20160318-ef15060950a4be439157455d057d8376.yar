rule sig_20160318_ef15060950a4be439157455d057d8376 {
  meta:
    description = "datamaliciousorder - file 20160318_ef15060950a4be439157455d057d8376.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d11e2d3392c242faa20cc48ca22a5df1ce8403454273e4c96f6d837750f9e49"

  strings:
    $s1  = "var ceZI = \"qPy!i\"[\"charAt\"](3);var vdzC = \"\\x61in\";var lwd = \"\\x79 a\\x67\";var x = \"\\x74r\";var mbx = \", \";var il" ascii
    $s2  = " + (function Vs(){return Y1;}()); oK = Mw(); zwr = WScript[(function Aga(){return GzBe;}()) + (function X(){return K0;}()) + (fu" ascii
    $s3  = "(JHo) + (function DqOMr(){return HJe;}())]();WScript[(function yMsBX(){return pEKq;}())](okDh());var sk = new this[(function ty0" ascii
    $s4  = "g(){return V0;}()) + (function FnX(){return s1;}()) + (vQAiM) + (function L0(){return OFBcK;}());}else{WScript.Echo((function FH" ascii
    $s5  = "(){return JHo;}()) + (function goaL(){return HJe;}())]();WScript[(function R(){return pEKq;}())](okDh());var sk = new this[(func" ascii
    $s6  = "Omthi) + (DyG) + (Ktu)] < 4 ) {WScript[(function eJC(){return pEKq;}())](okDh() * 10)};fob = WScript[Y()]((function h0(){return " ascii
    $s7  = "+ (function z(){return Wt;}());};function Y0(aDNR, V){return aDNR - V;};function Y(){return (function s0(){return GzBe;}()) + (f" ascii
    $s8  = "T() != 0){wG = true;K = true;break;}}function f() {return wG && K;};if (f()){itfg = QOIQY[(function OeU(){return VwYSm;}()) + (G" ascii
    $s9  = "ar hyqt = \"j\\x65c\\x74\";var K0 = \"t\\x65O\\x62\";var GzBe = \"C\\x72ea\";var QOIQY = function YfZh() {return WScript[(functi" ascii
    $s10 = "urn rIqd;}()) + (function j(){return wZs;}()) + (function Eq(){return cXh;}()) + (function qilFq(){return Mz;}())) + (function I" ascii
    $s11 = "()) + (function Ic(){return m0;}())]);fob[(function PHaX(){return AQslB;}()) + (function tvEJ(){return Ow0;}()) + (VXsr)] = 0;fo" ascii
    $s12 = ") + (function K1(){return qg;}()) + (function A(){return Ftt;}()) + (function gPF(){return VwDfi;}()) + (function vX(){return c0" ascii
    $s13 = ";}()) + (function ce(){return KQti;}()) + (function Rv(){return RYFHy;}()) + (function kZJ(){return is;}())]((function ajT(){ret" ascii
    $s14 = "KmBx;}()) + (function u(){return bmsq;}()) + (function B(){return Hi;}()) + (function oBRl(){return XB;}()) + (qnpyg) + (functio" ascii
    $s15 = "xZ(){return Bs;}()) + (function Pwee(){return IxqT;}()) + (a) + (function zAjI(){return goRg;}()) + (function hW(){return U;}())" ascii
    $s16 = " (lwd) + (function DEMON(){return vdzC;}()) + (function uZ(){return ceZI;}()));}" fullword ascii
    $s17 = "(function ReD(){return dWn;}()), false);zwr[(fw) + (function F(){return zh;}()) + (function N0(){return KIB;}())]();while (zwr[(" ascii
    $s18 = "nction uJNg(){return hP;}()) + (mia)]();var ncQP = sk[(en) + (function ikTc(){return Z0;}()) + (function h(){return DidA;}()) + " ascii
    $s19 = "tion fkqOd(){return hP;}()) + (function Rnkj(){return mia;}())]();var XPE = sk[(function mdM(){return en;}()) + (function r(){re" ascii
    $s20 = "return GzBe;}()) + (function rp(){return K0;}()) + (function T(){return hyqt;}())]((function w(){return D;}()) + (function Jsp()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}