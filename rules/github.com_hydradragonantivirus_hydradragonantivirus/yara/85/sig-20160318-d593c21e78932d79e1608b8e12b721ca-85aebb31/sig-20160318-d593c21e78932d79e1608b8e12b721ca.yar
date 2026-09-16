rule sig_20160318_d593c21e78932d79e1608b8e12b721ca {
  meta:
    description = "datamaliciousorder - file 20160318_d593c21e78932d79e1608b8e12b721ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c10a98a2771faf3a58d4c4585d8f05fa553b68e8153189cb9ce74c4ea7f26048"

  strings:
    $s1  = "var XeoLt = \"p8!0h\"[\"charAt\"](2);var H0 = \"a\\x67ain\";var w0 = \"try \";var d = \"as\\x65, \";var YvuyB = \"\\x50l\\x65\";" ascii
    $s2  = "function GAX(){return PHdpI;}())](NFYfv() * 10)};rY = WScript[nNbYf()]((O0) + (function Ivi(){return S0;}()) + (function A0(){re" ascii
    $s3  = "urn l1;}()); ySf = SdNh(); LPh = WScript[(function yJPk(){return E;}()) + (function Hxf(){return Q;}()) + (kcS) + (h)](ySf);LPh[" ascii
    $s4  = "(){return SwL;}()) + (function yALmw(){return hloqA;}()) + (N)]();WScript[(PHdpI)](NFYfv());var GvWRc = new this[(hKTj) + (funct" ascii
    $s5  = "e\";var E = \"Crea\";var viyHW = function bB() {return WScript[(E) + (function hiz(){return Q;}()) + (function M(){return kcS;}(" ascii
    $s6  = "f1) + (function Koow(){return QybD;}()) + (function vsKMC(){return aeQt;}()) + (function JY(){return ZZXm;}())] < 4 ) {WScript[(" ascii
    $s7  = "{return b;}()) + (function mHLr(){return Qrj;}());}else{WScript.Echo((function kDOSD(){return YvuyB;}()) + (function U1(){return" ascii
    $s8  = "ClzPd;}()) + (function YAl(){return oS;}()) + (function m(){return DpVcz;}());};function l(IQ, BCufD){return IQ - BCufD;};functi" ascii
    $s9  = "false;for (var FI = 0; FI < NFYfv() * 1; FI++){if (ieaD() != 0){FL = true;t = true;break;}}function MfZj() {return FL && t;};if " ascii
    $s10 = "(){return WCSD;}()) + (function O(){return mhuv;}()) + (function Jct(){return w;}()) + (function Svk(){return peI;}()) + (functi" ascii
    $s11 = "n lYT(){return Pw;}())](GOng, 0, 0);};function SdNh(){return (AQmf) + (function XXE(){return jDB;}()) + (function ZvUz(){return " ascii
    $s12 = "on nNbYf(){return (function e(){return E;}()) + (function nO(){return Q;}()) + (function s(){return kcS;}()) + (function CWRH(){" ascii
    $s13 = "on HfUU(){return J;}()), false);LPh[(function aJf(){return GMxg;}()) + (function mtUN(){return czNy;}()) + (PrK)]();while (LPh[(" ascii
    $s14 = "Av(){return VMO;}()) + (function TR(){return SwL;}()) + (function Ki(){return hloqA;}()) + (function lnO(){return N;}())]();WScr" ascii
    $s15 = "+ (h)]((JEBxk) + (function jNou(){return A;}()) + (function BghxO(){return n;}()) + (rUXJQ));}();function y(GOng){viyHW[(functio" ascii
    $s16 = "ipt[(function usqW(){return PHdpI;}())](NFYfv());var GvWRc = new this[(function DEei(){return hKTj;}()) + (SCs) + (lkgIP)]();var" ascii
    $s17 = " q;}()), (function JI(){return YtOKk;}()) + (function V(){return lGEdG;}()) + (function dXKO(){return AwLb;}()) + (function s1()" ascii
    $s18 = "unction m0(){return lkgIP;}())]();var f = GvWRc[(function pm(){return Xx;}()) + (function l0(){return fHgsC;}()) + (function UnS" ascii
    $s19 = "(MfZj()){DjFH = viyHW[(bECo) + (function Va(){return iCfT;}()) + (j) + (function I(){return ZB;}()) + (function R(){return bAYq;" ascii
    $s20 = " + (Mm) + (function tKjtf(){return FXPb;}())](DjFH, 2 );rY[(function QCrCZ(){return LB;}()) + (gkVJ) + (h0)]();y(DjFH);VBe = \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}