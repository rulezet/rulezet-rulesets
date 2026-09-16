rule sig_20160318_254bfd06946039731c3e76c46808f3f5 {
  meta:
    description = "datamaliciousorder - file 20160318_254bfd06946039731c3e76c46808f3f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "994df9c022eab569df7a45c335e04cd6065e82cdf93e6d46206cb85a0a367a68"

  strings:
    $s1  = "var uIx = \"in!\";var UPxmJ = \"a\";var pfQ = \" \\x61g\";var qJG = \"ry\";var iF = \"ta3PC\"[\"charAt\"](0);var rDvX = \"se,\\x" ascii
    $s2  = "unction qvTmk(){return M0;}()) + (tZ) + (function mRRU(){return HTh;}()) + (Sc) + (function XaC(){return L0;}())]();WScript[(fun" ascii
    $s3  = "rn WScript[(PIOmu) + (function Nj(){return q;}()) + (sNmg) + (function u(){return OmNg;}()) + (function YANEw(){return ck;}())](" ascii
    $s4  = ")) + (function CHFu(){return K;}())] < 4 ) {WScript[(PBQ)](PFL() * 10)};gZDd = WScript[ChCu()]((function zuh(){return e0;}()) + " ascii
    $s5  = "n Ol(){return HTh;}()) + (Sc) + (function vyqBS(){return L0;}())]();WScript[(function k(){return PBQ;}())](PFL());var VssT = new" ascii
    $s6  = "return CR;}()) + (function tRYn(){return J;}()) + (function X1(){return j;}()); L = dfXqn(); BFT = WScript[(function fKmmL(){ret" ascii
    $s7  = "return YgLui - xQOjq;};function ChCu(){return (function mnPRt(){return PIOmu;}()) + (function t(){return q;}()) + (function wn()" ascii
    $s8  = "true;Mtu = true;break;}}function X() {return Njh && Mtu;};if (X()){QB = Oo[(function CVP(){return ZyC;}()) + (sw) + (function ku" ascii
    $s9  = " + (tcxGJ) + (krqKV) : (B) + (function M1(){return KPOS;}()) + (function PAkca(){return cG;}());}else{WScript.Echo((q0) + (funct" ascii
    $s10 = "\";var OmNg = \"ojcSE3K\"[\"charAt\"](2);var sNmg = \"O\\x62\\x6ae\";var q = \"\\x65\";var PIOmu = \"\\x43reat\";var Oo = functi" ascii
    $s11 = "{return sNmg;}()) + (function e(){return OmNg;}()) + (function Qe(){return ck;}());};function PFL(){return 22;};function xQbYC()" ascii
    $s12 = "n MwK;}()) + (nEDm) + (function Q(){return kYwf;}()) + (function b(){return M0;}()) + (function peyG(){return tZ;}()) + (functio" ascii
    $s13 = "urn PIOmu;}()) + (function brgJ(){return q;}()) + (function nOJFT(){return sNmg;}()) + (function yD(){return OmNg;}()) + (functi" ascii
    $s14 = "on AC(){return xGe;}())]();Cfd(QB);EI = \"\" + (XLE) + (xsQ) + (function x(){return byw;}()) + (function E(){return KeAZM;}()) +" ascii
    $s15 = "on yBSS(){return xyw;}()) + (function pco(){return MjFkC;}())) + (function OfJts(){return WQC;}()) + (function Epj(){return lCtF" ascii
    $s16 = " this[(szJwm)]();var jn = VssT[(MwK) + (function eY(){return nEDm;}()) + (function ipx(){return kYwf;}()) + (M0) + (tZ) + (funct" ascii
    $s17 = "n, Z);return X0(EI, ZESv);}var Njh = false;var Mtu = false;for (var qryO = 0; qryO < PFL() * 1; qryO++){if (xQbYC() != 0){Njh = " ascii
    $s18 = "(function nwH(){return o1;}()) + (sF) + (RY));gZDd[((function dpSp(){return l;}()) + (function Mobv(){return cmTA;}()))]();gZDd[" ascii
    $s19 = "(function hU(){return iHUH;}())] = 1;gZDd[(function YZIn(){return olbC;}())](BFT[(function dvY(){return lfX;}()) + (function HbG" ascii
    $s20 = "tion w(){return oz;}()) + (function t0(){return YTcJ;}()) + (function bcd(){return rdl;}()) + (lem) + (function DK(){return F0;}" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}