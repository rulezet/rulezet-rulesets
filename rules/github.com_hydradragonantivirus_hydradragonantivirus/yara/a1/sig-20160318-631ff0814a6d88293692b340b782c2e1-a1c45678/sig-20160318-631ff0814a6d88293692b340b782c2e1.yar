rule sig_20160318_631ff0814a6d88293692b340b782c2e1 {
  meta:
    description = "datamaliciousorder - file 20160318_631ff0814a6d88293692b340b782c2e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0419c68bb9ed7792d2f427ea6d48c51408e98ae6f0d6f98ac21e06e5177984e"

  strings:
    $s1  = "var XST = \"a\\x69\\x6e!\";var u0 = \"ag\";var ZP = \"\\x79 \";var HR = \"\\x74r\";var LOU = \"e, \";var DMt = \"s\";var Sk = \"" ascii
    $s2  = ";}()) + (function QwOL(){return qjla;}()) + (function cBVOw(){return vWQe;}()); Fv = tL(); uj = WScript[(vE) + (Jev) + (function" ascii
    $s3  = "}()) + (function Qfbu(){return KO;}()) + (function k(){return Z;}())]();WScript[(function WQY(){return bRm;}()) + (vkNm)](nduOW(" ascii
    $s4  = "}()), false);uj[(function nBxWx(){return Si;}())]();while (uj[(WetY) + (function XGx(){return TjW;}()) + (usZL)] < 4 ) {WScript[" ascii
    $s5  = "()) + (function S0(){return kEGu;}()) : (function P3(){return yQ;}()) + (bLLU) + (LlrV);}else{WScript.Echo((function tb(){return" ascii
    $s6  = "(bRm) + (function tjsnm(){return vkNm;}())](nduOW() * 10)};KWpz = WScript[g()]((xaF) + (function Z1(){return j;}()) + (SlMD) + (" ascii
    $s7  = "Ev;}()) + (function XEG(){return KO;}()) + (function eHBpV(){return Z;}())]();WScript[(bRm) + (vkNm)](nduOW());var Umzx = new th" ascii
    $s8  = "eturn CoqW;}());};function f(F, P0){return F - P0;};function g(){return (function A(){return vE;}()) + (function guLt(){return J" ascii
    $s9  = ");function UjUWm(c){qTb[(function LWr(){return ohpRn;}())](c, 0, 0);};function tL(){return (function aGHIE(){return wSAM;}()) + " ascii
    $s10 = "nction Jk() {return ZOgwB && wCUYD;};if (Jk()){iB = qTb[(Vsewx) + (function APIEe(){return C1;}()) + (function BM(){return juOWs" ascii
    $s11 = "o\\x70e\";var cVC = \"louM8mwa\"[\"charAt\"](5);var SlMD = \"r\\x65a\";var j = \".S\\x74\";var xaF = \"ADOD\\x42\";var nS = \"p" ascii
    $s12 = " Sk;}()) + (function tHu(){return DMt;}()) + (function zC(){return LOU;}()) + (function Ehr(){return HR;}()) + (ZP) + (u0) + (fu" ascii
    $s13 = "cVC));KWpz[((Er) + (function gZAzk(){return mHtn;}()))]();KWpz[(dXl) + (function K(){return ur;}())] = 1;KWpz[(function ZhK(){re" ascii
    $s14 = "(function pGoS(){return C0;}()) + (ZzcfC) + (function gsdjZ(){return Gx;}()) + (function jNY(){return vx;}()) + (function LX(){r" ascii
    $s15 = "ev;}()) + (function r0(){return Neuz;}()) + (function C(){return hRm;}());};function nduOW(){return 22;};function fLN(){var Umzx" ascii
    $s16 = " = new this[(function FdUJX(){return YqhW;}()) + (function N(){return o0;}())]();var esnTX = Umzx[(Im) + (function Wmf(){return " ascii
    $s17 = "SJ(){return av;}()) + (function lHhBp(){return eSI;}()) + (function zkqJu(){return w0;}()) + (eNzl) + (function tlNk(){return u;" ascii
    $s18 = "{return N0;}()) + (oWs) + (function FY(){return HE;}())] = 0;KWpz[(function GoIPY(){return KO0;}()) + (function yMA(){return F0;" ascii
    $s19 = "ion dmGY(){return Tbk;}()) + (function WsORu(){return L0;}()) + (function fOmN(){return igWi;}()) + (function CM(){return YWygn;" ascii
    $s20 = "ction WcT(){return xGi;}())) + (function ualm(){return abjKi;}()) + (function VWonA(){return E;}()) + (function LRSGS(){return S" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}