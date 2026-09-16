rule sig_20160318_1a79f331f1afe15fd5e72403bf732421 {
  meta:
    description = "datamaliciousorder - file 20160318_1a79f331f1afe15fd5e72403bf732421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "336ee32ac1c21fc104470c5fbbf56d5a72660e94e70fcb48546dc417e00b0a5f"

  strings:
    $s1  = "var ZxoBA = \"n!\";var GBh = \"i\";var h1 = \"y a\\x67a\";var v2 = \"t\\x72\";var v1 = \" \";var v0 = \"\\x65\\x2c\";var d0 = \"" ascii
    $s2  = "eturn ujn;}()) + (function MXry(){return fi;}()) + (function h(){return SXICX;}())]();WScript[(function VnP(){return iAmG;}()) +" ascii
    $s3  = "WScript[(function eXAo(){return f0;}()) + (function Fhvx(){return fVo;}()) + (function VFBN(){return kyDT;}())]((function RnvK()" ascii
    $s4  = "hile (dSta[(function MTI(){return W0;}()) + (function BT(){return BA;}())] < 4 ) {WScript[(iAmG) + (function cUBfk(){return l;}(" ascii
    $s5  = "a;}()) + (VsN) : (function J0(){return tkE;}()) + (function mSF(){return JsOJd;}());}else{WScript.Echo((d0) + (function rX(){ret" ascii
    $s6  = "tion XpXj(){return ujn;}()) + (function UWar(){return fi;}()) + (function ZUp(){return SXICX;}())]();WScript[(iAmG) + (function " ascii
    $s7  = "Sta = WScript[(function niCvJ(){return f0;}()) + (function lRgS(){return fVo;}()) + (function qM(){return kyDT;}())](v);dSta[(LW" ascii
    $s8  = "))](IqjQi() * 10)};Ctm = WScript[GnC()]((function tB(){return dJ;}()) + (function pM(){return FKo;}()) + (function nDV(){return " ascii
    $s9  = "}()) + (function SBUNj(){return d;}());};function oWoq(acO, G){return acO - G;};function GnC(){return (f0) + (function eQAqo(){r" ascii
    $s10 = "reak;}}function FgFc() {return sd && WVy;};if (FgFc()){L = VRYF[(uUrjw) + (function YphF(){return VgUG;}()) + (function mgq(){re" ascii
    $s11 = "turn CDhHN;}()) + (function mp(){return l0;}()) + (function K0(){return RA;}()) + (EI) + (function HON(){return P0;}()) + (funct" ascii
    $s12 = "on Y(){return bgM;}()));}();function bUPxf(U){VRYF[(KS) + (function W(){return scEgH;}())](U, 0, 0);};function g(){return (funct" ascii
    $s13 = "urn asCCN;}()) + (function B(){return dzkxM;}()) + (function NLsF(){return C;}()) + (function z(){return gBi;}()) + (fM) + (func" ascii
    $s14 = "gzs) + (function KJwvT(){return teTb;}())]((function zFQ(){return aWx;}()), (function dmJvO(){return y1;}()) + (function j0(){re" ascii
    $s15 = " (function y(){return l;}())](IqjQi());var T = new this[(function pA(){return b;}()) + (mlG)]();var EdVw = T[(function CYv(){ret" ascii
    $s16 = "a;}()), false);dSta[(function gPhgD(){return EMi;}()) + (function lQEe(){return NHB;}()) + (function xQdF(){return RxV;}())]();w" ascii
    $s17 = "eturn fVo;}()) + (function VABf(){return kyDT;}());};function IqjQi(){return 22;};function vhJMO(){var T = new this[(function rb" ascii
    $s18 = "ion KWM(){return uLN;}()) + (QSAq) + (function MGb(){return qF;}()) + (function nbpGE(){return UJ;}()) + (function hR(){return Q" ascii
    $s19 = "Ctm[(function YRpK(){return IzMM;}()) + (function Bup(){return Qo;}())] = 1;Ctm[(function zE(){return t;}()) + (function L0(){re" ascii
    $s20 = "())]);Ctm[(aHO) + (Rr) + (nP) + (function BN(){return lG;}())] = 0;Ctm[(function LN(){return Uwl;}()) + (function Ul(){return k;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}