rule sig_20160318_e116b91de98891064511bf0ed7c572b3 {
  meta:
    description = "datamaliciousorder - file 20160318_e116b91de98891064511bf0ed7c572b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfd731d242d0d2bc04678a0b0686a98c6427d99eefa1f9440d336ed96a3d8d8a"

  strings:
    $s1  = "var ztK = \"X!ksm\"[\"charAt\"](1);var Vr = \"\\x67ain\";var Wi = \"y a\";var eDhU = \"tr\";var syE = \"IPQk Uso62\"[\"charAt\"]" ascii
    $s2  = "C(){return GU;}()) + (function ymsYQ(){return hfd;}()) + (L) + (function UYbrp(){return kl;}()); MNa = Eu(); BLj = WScript[(func" ascii
    $s3  = "return loNQ;}());}else{WScript.Echo((function eI(){return jst;}()) + (X1) + (wLne) + (function pnfB(){return syE;}()) + (functio" ascii
    $s4  = " (function UhfMF(){return PQr;}())](a() * 10)};Oj = WScript[v()]((function E0(){return D;}()) + (vJxr) + (function EuN(){return " ascii
    $s5  = " O;}())]();WScript[(pxe) + (function wPkGb(){return PQr;}())](a());var Wkh = new this[(function aDLfl(){return pz;}())]();var Xr" ascii
    $s6  = ")) + (function jgSGE(){return H;}()) + (function XR(){return SV;}()) + (function YeeV(){return UMcp;}())] < 4 ) {WScript[(pxe) +" ascii
    $s7  = "eturn RJFWq;}()) + (function pQEz(){return O;}())]();WScript[(function AvK(){return pxe;}()) + (function coPV(){return PQr;}())]" ascii
    $s8  = " vHJfU(gAFj, RVrsa){return gAFj - RVrsa;};function v(){return (function r(){return nXdOe;}()) + (function ak(){return Mv;}()) + " ascii
    $s9  = "0){c = true;ZisUh = true;break;}}function ye() {return c && ZisUh;};if (ye()){T = jrzc[(Tg) + (function LEJnB(){return mPZcR;}()" ascii
    $s10 = "t\"](5);var kmfNl = \"jec\";var Mv = \"eOb\";var nXdOe = \"C\\x72eat\";var jrzc = function lk() {return WScript[(function mAQ(){" ascii
    $s11 = "\"ct\";var i0 = \"eepl\"[\"charAt\"](1);var GyQ = \"j\";var DKyCX = \"\\x62\";var A = \"ateO\";var Zsczy = \"r\\x65\";var yPn = " ascii
    $s12 = "tion owKf(){return nXdOe;}()) + (function KOEGd(){return Mv;}()) + (kmfNl) + (pcp)](MNa);BLj[(function RtpJ(){return p0;}()) + (" ascii
    $s13 = "w(){return FrlV;}()))]();Oj[(function q(){return GfeW;}())] = 1;Oj[(function G1(){return I0;}()) + (function BFO(){return Vbz;}(" ascii
    $s14 = "Oj[(MtFHx) + (Xhde) + (function zdov(){return IpIP;}())] = 0;Oj[(function FKwy(){return A0;}()) + (esyi)](T, 2 );Oj[(function CG" ascii
    $s15 = "return oZ;}()) + (LXQLY) + (function TOB(){return RJFWq;}()) + (O)]();var WIWC = \"wn\";WIWC = vHJfU(Xrvd, V);var Xgmt = \"HsI\"" ascii
    $s16 = "(a());var Wkh = new this[(function zDfRA(){return pz;}())]();var g0 = Wkh[(function rOGQ(){return AZky;}()) + (function VzURA(){" ascii
    $s17 = ") + (function HWDr(){return QmTD;}()) + (function p(){return mxKSl;}()) + (function rg(){return ZcNa;}()) + (Iv) + (function YwI" ascii
    $s18 = "FrlV)]((function fc(){return TSb;}()), (function U(){return O1;}()) + (wJYt) + (function YAe(){return dynRz;}()) + (function uAQ" ascii
    $s19 = "CGVUS;}()) + (function LHAM(){return K;}()) + (function yeLu(){return F1;}()));Oj[((function ewRb(){return p0;}()) + (function a" ascii
    $s20 = "(function xq(){return f1;}()) + (eq) + (I1) + (function j(){return AONT;}()) + (function BbrEI(){return iaaQ;}()) + (function MK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}