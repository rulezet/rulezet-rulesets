rule sig_20160318_0c99233bb2ccc803171ee966f77184c5 {
  meta:
    description = "datamaliciousorder - file 20160318_0c99233bb2ccc803171ee966f77184c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2602204874725cfde483ea7ef617bde4b96144822eb6262b98974b4264b2344a"

  strings:
    $x1  = "var w = \"a\\x69n!\";var HmHL = \"g\";var d0 = \"try a\";var MKKip = \"e\\x2c \";var oQy = \"Pleas\";var oADL = \"62\";var Xibh " ascii
    $s2  = "on XcoQW(){return czhqw;}())]();WScript[(function Nol(){return NM;}()) + (function r(){return sj;}())](jfbUA());var QwENt = new " ascii
    $s3  = " function qj() {return WScript[(function Os(){return hnw;}()) + (function Y(){return Aul;}()) + (M) + (function VwlR(){return LZ" ascii
    $s4  = "+ (VrPrV) + (Jhj) + (eW) + (czhqw)]();WScript[(function pNnM(){return NM;}()) + (function DMuq(){return sj;}())](jfbUA());var Qw" ascii
    $s5  = "}()) + (vDgsX) + (function OhA(){return Xibh;}()) + (function ZIkB(){return oADL;}());}else{WScript.Echo((function V1(){return o" ascii
    $s6  = "jfbUA() * 10)};BdMO = WScript[ii()]((function wZdR(){return JXBa;}()) + (dD) + (function u(){return LEGXz;}()) + (OllB));BdMO[((" ascii
    $s7  = "dNwZ = WScript[(function M0(){return hnw;}()) + (function zJGBM(){return Aul;}()) + (function TOfpN(){return M;}()) + (function " ascii
    $s8  = "iXveW(){return QQaQ;}()) + (function UjJiK(){return JorlN;}()) + (function Stk(){return iJtoC;}())] < 4 ) {WScript[(NM) + (sj)](" ascii
    $s9  = "{return wrONz - dZ;};function ii(){return (hnw) + (function Kz(){return Aul;}()) + (function RkiIo(){return M;}()) + (function F" ascii
    $s10 = "function NFvYU() {return gkad && IBap;};if (NFvYU()){gtyt = IaDM[(function b(){return EtEWS;}()) + (function geGo(){return XYf;}" ascii
    $s11 = "()) + (function gLwgU(){return xnRAu;}()) + (function s(){return OK;}()) + (Agf) + (nY) + (function RdE(){return sQDvU;}())]((fu" ascii
    $s12 = " (function Og(){return mfw;}())]();while (dNwZ[(function aqkOA(){return sdl;}()) + (function R0(){return CRUYh;}()) + (function " ascii
    $s13 = "function cHB(){return Z;}()) + (function J(){return MKlM;}()) + (wUJnZ) + (pruh), false);dNwZ[(function ixRQN(){return ho;}()) +" ascii
    $s14 = "+ (SxVmu)]();lX(gtyt);PE = \"\" + (sezxk) + (function nGj(){return oh;}()) + (XFFYo) + (function W(){return IxWMt;}()) + (oxw) +" ascii
    $s15 = "unction ZloK(){return BURJ;}()) + (function zbPl(){return wQi;}()) + (qBlhc)]();var pJ = QwENt[(function leks(){return lwW;}()) " ascii
    $s16 = "nction JuALX(){return D;}()) + (function swGYU(){return EZxns;}())) + (function VHX(){return q0;}()) + (function ksPxH(){return " ascii
    $s17 = "return u0;}()) + gkad ? (function wmx(){return cPTOn;}()) + (jWFwE) : (function J0(){return FXWz;}()) + (function v(){return yv;" ascii
    $s18 = ");function lX(Rh){IaDM[(function y(){return q;}())](Rh, 0, 0);};function oUadM(){return (function Lzv(){return t;}()) + (hWK) + " ascii
    $s19 = "this[(function cjqvS(){return BURJ;}()) + (function lrP(){return wQi;}()) + (function nyc(){return qBlhc;}())]();var ao = QwENt[" ascii
    $s20 = "ction GvKO(){return YVdpe;}()) + (LXHe) + (pIQkZ) + (Blwa) + (function b0(){return QXvE;}()) + (function Nz(){return IV;}()) + (" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}