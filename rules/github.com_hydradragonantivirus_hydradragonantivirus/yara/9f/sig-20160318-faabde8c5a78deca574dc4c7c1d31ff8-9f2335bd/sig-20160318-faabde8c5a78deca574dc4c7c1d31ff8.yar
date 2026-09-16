rule sig_20160318_faabde8c5a78deca574dc4c7c1d31ff8 {
  meta:
    description = "datamaliciousorder - file 20160318_faabde8c5a78deca574dc4c7c1d31ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efda602cd5d232e6f6365adfa51a81c5201df0cf5c20cc39c0fac1484d67094b"

  strings:
    $x1  = "var mJKcM = \"n!\";var XaXUd = \"\\x67ai\";var jp = \"\\x72y a\";var cHwr = \" \\x74\";var jRX = \"\\x65ase\\x2c\";var dnwQm = " ascii
    $s2  = "ion ZYs(){return h;}()) + (hPW)](FlkM() * 10)};WZiJX = WScript[nUWd()]((rlYB) + (function FGNdQ(){return oBph;}()) + (function A" ascii
    $s3  = "()) + (function c1(){return AsnCY;}()) + (function SKpj(){return q0;}()) + (function uS(){return OjF;}())] < 4 ) {WScript[(funct" ascii
    $s4  = ";var kP = \"Cr\\x65\\x61\\x74\";var JH = function g() {return WScript[(function qBVH(){return kP;}()) + (function NXZMH(){return" ascii
    $s5  = "eturn oK;}()) + (function UlUah(){return L0;}()) + (nkFUM) + (function gIY(){return atz;}())]();WScript[(function uOFUc(){return" ascii
    $s6  = " m = WScript[(function PF(){return kP;}()) + (function UBW(){return yGLcr;}()) + (function c(){return Tw;}()) + (function hEO(){" ascii
    $s7  = " (function PNnYd(){return iacG;}()) + (ygJ);}else{WScript.Echo((function oYF(){return dnwQm;}()) + (function TvcUV(){return jRX;" ascii
    $s8  = "eturn atz;}())]();WScript[(function nPV(){return h;}()) + (hPW)](FlkM());var bIUdt = new this[(function DB(){return KW;}())]();v" ascii
    $s9  = "());};function hF(jpbZ, vB){return jpbZ - vB;};function nUWd(){return (function HCgBP(){return kP;}()) + (function ZD(){return y" ascii
    $s10 = "ue;nnS = true;break;}}function wsx() {return VS && nnS;};if (wsx()){iJ = JH[(function oRfV(){return k;}()) + (E) + (function iLx" ascii
    $s11 = "F(qSAL, tqGO);return hF(L, RZdg);}var VS = false;var nnS = false;for (var ql = 0; ql < FlkM() * 1; ql++){if (leU() != 0){VS = tr" ascii
    $s12 = "\" + (function VuvSw(){return DU;}()) + (pOM) + (function fVdhY(){return OgcJ;}()) + (function IV(){return bVV;}()) + (function " ascii
    $s13 = "GLcr;}()) + (function BppVu(){return Tw;}()) + (Wy);};function FlkM(){return 22;};function leU(){var bIUdt = new this[(function " ascii
    $s14 = "urn mgT;}()) + (function mDta(){return NY;}()) + (function IPI(){return JUk;}()) + (Qi) + (function gJfN(){return v0;}()) + (fun" ascii
    $s15 = "+ (function IICz(){return iAW;}()) + (function M(){return J0;}()) + (function H(){return EFq;}()) + (iJ0) + (tHf); fiG = HWNq();" ascii
    $s16 = "urn IYH;}()) + VS ? (function gOmOR(){return l;}()) + (function Sw(){return Z1;}()) + (JBns) : (function wqSm(){return nI;}()) +" ascii
    $s17 = "Tu(){return ok;}()) + (VHf) + (avlJz) + (function zB(){return RIW;}()) + (function Wnwg(){return Uu;}()) + (function Yvyan(){ret" ascii
    $s18 = "](m[(vC) + (function bFF(){return zzh;}()) + (function CvrH(){return tG;}()) + (function Ci(){return QFx;}()) + (CX) + (function" ascii
    $s19 = "tion QaTc(){return D;}()) + (function lc(){return wg;}()) + (function ToRA(){return oK;}()) + (L0) + (nkFUM) + (function gZN(){r" ascii
    $s20 = "K;}()) + (function mXF(){return X;}()), false);m[(function gU(){return iLYA;}()) + (Ct)]();while (m[(function QcQR(){return O0;}" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}