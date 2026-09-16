rule sig_20160318_3580179fea554034064d68747709a01f {
  meta:
    description = "datamaliciousorder - file 20160318_3580179fea554034064d68747709a01f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c7e6129a73a036c2f672ed4fdc21ab227762eeec5c31b4452bd697d9528f5ac"

  strings:
    $s1  = "var y0 = \"in!\";var zjWo = \"\\x67a\";var kF = \" \\x61\";var XE = \"t\\x72y\";var xajAY = \"\\x20\";var Xt = \"ease,\";var Ll " ascii
    $s2  = "eturn U0;}());}else{WScript.Echo((Ll) + (function fhYQa(){return Xt;}()) + (function nme(){return xajAY;}()) + (function H(){ret" ascii
    $s3  = "){return ywxHV;}()) + (function YjyR(){return lg;}())]();WScript[(function p(){return ckF;}()) + (function fg(){return P;}())](R" ascii
    $s4  = "ript[(function Ab(){return ckF;}()) + (function viOx(){return P;}())](REwFI() * 10)};M = WScript[TzMcv()]((nhiQx) + (rF) + (func" ascii
    $s5  = ";var vJ = function aF() {return WScript[(function vxMA(){return B;}()) + (HzF) + (function X(){return Jy;}()) + (function Yh(){r" ascii
    $s6  = "urn d;}()) + (CNOYp); fZTe = BpAEl(); oq = WScript[(function DBn(){return B;}()) + (function zKCme(){return HzF;}()) + (function" ascii
    $s7  = ") + (VQqAA) + (ywxHV) + (function eT(){return lg;}())]();WScript[(function VKPLl(){return ckF;}()) + (P)](REwFI());var atkyr = n" ascii
    $s8  = "turn w - vEi;};function TzMcv(){return (function xnRxl(){return B;}()) + (function U(){return HzF;}()) + (function JjdTs(){retur" ascii
    $s9  = "0; k < REwFI() * 1; k++){if (j() != 0){Qj = true;wt = true;break;}}function Qfzc() {return Qj && wt;};if (Qfzc()){I = vJ[(functi" ascii
    $s10 = "rn tqSy;}()) + (function Rdf(){return gd;}()) + (function Wed(){return jQ;}()), false);oq[(function T(){return YsglZ;}()) + (fun" ascii
    $s11 = "K) + (function Qlrgn(){return zat;}()) + (function pyNa(){return bzoZ;}()) + (function Tp(){return P0;}()) + (function yf(){retu" ascii
    $s12 = "tion B0(){return LMdEI;}()) + (pd));M[((function FYd(){return MR;}()) + (function m0(){return xYHHK;}()))]();M[(wPPOl) + (functi" ascii
    $s13 = "F(){return WG;}()) + (function o(){return nR;}()) + (function w1(){return wRzp;}()) + (function kRA(){return AZV;}())](I, 2 );M[" ascii
    $s14 = ") + (siIH) + (function QMj(){return gSN;}()) + (function wXL(){return fT;}()) + (function GwvQ(){return a;}()) + (function Ug(){" ascii
    $s15 = " Rle;}())]();var u = atkyr[(IuuWh) + (R0) + (function YCIfp(){return SW;}()) + (function gBm(){return VQqAA;}()) + (function ch(" ascii
    $s16 = "on rfN(){return e;}())] = 1;M[(function Q0(){return y;}()) + (function zUX(){return iukX;}())](oq[(function zvKsw(){return kxiMY" ascii
    $s17 = "urn XE;}()) + (function ztmF(){return kF;}()) + (zjWo) + (function Dicj(){return y0;}()));}" fullword ascii
    $s18 = " + (function FEKJN(){return R;}()) + (function AAzfn(){return iEZ;}()));}();function KQaEw(WLkB){vJ[(function CE(){return VNtD;}" ascii
    $s19 = "rn mjSw;}()) + (nLta) + (uhp) + (function ohw(){return FFPL;}()) + (function mMJNh(){return rJm;}());};function XGsPV(w, vEi){re" ascii
    $s20 = " + (function qbPQ(){return oM;}()) + (wO) + (K0) + (function dJy(){return d0;}()) + (pKR) + Qj ? (function l2(){return ZMkAK;}()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}