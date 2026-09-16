rule sig_20160318_376e4e2d8e38efaf8a26ce678f3b5068 {
  meta:
    description = "datamaliciousorder - file 20160318_376e4e2d8e38efaf8a26ce678f3b5068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31c2046a3e78f6e29d9d8011f4bda84b72078543dbfbcbd0f86c44975ec8b3cb"

  strings:
    $s1  = "var QZc = \"i\\x6e\\x21\";var n1 = \"y a\\x67a\";var yQz = \"\\x2c tr\";var oWP = \"se\";var i0 = \"Plea\";var oVrB = \"162\";va" ascii
    $s2  = " + (function MaO(){return SMKje;}()) + (Dc); lzVas = C0(); UOWQ = WScript[(function LUzX(){return HRVsv;}()) + (function JZ(){re" ascii
    $s3  = "IXN;}()) + (function Vl(){return n;}()) + (function QGYu(){return xuz;}())](fSGT() * 10)};O = WScript[ijRzE()]((function r(){ret" ascii
    $s4  = "(function xif(){return tJ;}())]();WScript[(cIXN) + (n) + (xuz)](fSGT());var wj = new this[(function H0(){return pnbwI;}())]();va" ascii
    $s5  = "n Zf;}()) + (function CuXiR(){return Weglf;}()) + (oVrB);}else{WScript.Echo((function vPWp(){return i0;}()) + (function wuGEu(){" ascii
    $s6  = "nction lW(){return aAO;}())]();while (UOWQ[(O1) + (function ck(){return SxeX;}()) + (QgC)] < 4 ) {WScript[(function X(){return c" ascii
    $s7  = "nction MsK(){return tJ;}())]();WScript[(cIXN) + (function hoE(){return n;}()) + (function KSVw(){return xuz;}())](fSGT());var wj" ascii
    $s8  = "() {return WScript[(HRVsv) + (function Fxr(){return wnc;}()) + (function obl(){return mPpP;}()) + (function wS(){return rg;}()) " ascii
    $s9  = ")) + (function l(){return ujc;}()) + (function pZ(){return uexKe;}());};function Cf(P, cZ){return P - cZ;};function ijRzE(){retu" ascii
    $s10 = "se;for (var iRm = 0; iRm < fSGT() * 1; iRm++){if (waXiP() != 0){Tw = true;iIc = true;break;}}function tK() {return Tw && iIc;};i" ascii
    $s11 = "fhKNv = wj[(Bcm) + (zNaYI) + (function SaB(){return Q;}()) + (function tDVuq(){return vr;}()) + (function VZ(){return zj;}()) + " ascii
    $s12 = "bEY(){return Gb;}())]((qs) + (function lBtE(){return UZWg;}()) + (function lXu(){return Lj;}()), (function ud(){return vmt;}()) " ascii
    $s13 = "I;}()) + (function iLhsL(){return Q;}()) + (function JKh(){return vr;}()) + (function i(){return zj;}()) + (function VQPv(){retu" ascii
    $s14 = "turn F1;}()) + (function od(){return VXJA;}()) + (function F2(){return Q0;}()) + (function iGUUO(){return m;}()) + (function oCH" ascii
    $s15 = " + (function e(){return hYlpU;}()) + (gp) + (function Z0(){return cSpfQ;}())]((function DZWyb(){return rQA;}()) + (function nO()" ascii
    $s16 = "r J = wj[(Bcm) + (function XSM(){return zNaYI;}()) + (function rFUSO(){return Q;}()) + (function K(){return vr;}()) + (zj) + (fu" ascii
    $s17 = "+ (PEC) + (function RnhC(){return cWbmP;}()) + (function lQDV(){return piX;}()) + (function Y0(){return yI;}()) + (function tR()" ascii
    $s18 = " = new this[(function xmEJc(){return pnbwI;}())]();var LqU = wj[(function bqPyt(){return Bcm;}()) + (function HhFK(){return zNaY" ascii
    $s19 = "(function Sqb(){return O0;}()) + (function TJ(){return WW;}()) + (ZEi) + (JimL), false);UOWQ[(function vML(){return p;}()) + (fu" ascii
    $s20 = "return Hr;}())]();d(aYS);c = \"\" + (function lPevY(){return cL;}()) + (function jxUGv(){return Qx;}()) + (function EiRk(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}