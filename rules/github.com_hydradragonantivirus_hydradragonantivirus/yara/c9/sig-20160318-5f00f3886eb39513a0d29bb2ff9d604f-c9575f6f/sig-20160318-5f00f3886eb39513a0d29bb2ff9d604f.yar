rule sig_20160318_5f00f3886eb39513a0d29bb2ff9d604f {
  meta:
    description = "datamaliciousorder - file 20160318_5f00f3886eb39513a0d29bb2ff9d604f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e891ca2a9e872f3b5b2d8fdcf6dc9690cd6252631a5f0b5ca69df646e92f9500"

  strings:
    $x1  = "var bol = \"a\\x69n\\x21\";var uMO = \"y\\x20a\\x67\";var NoQf = \"e\\x2c\\x20tr\";var YrdkM = \"s\";var YJst = \"Ple\\x61\";var" ascii
    $s2  = "}())]();WScript[(function JyJ(){return E;}()) + (hDwZ) + (function vK(){return nIuxx;}())](Gut());var zrW = new this[(function i" ascii
    $s3  = "(function J(){return kFKP;}()) + (g);}else{WScript.Echo((function kP(){return YJst;}()) + (function pfEb(){return YrdkM;}()) + (" ascii
    $s4  = " ZK(){return Olj;}())]();while (uEx[(nTNkl) + (function jV(){return H0;}()) + (function Zj(){return b;}())] < 4 ) {WScript[(func" ascii
    $s5  = "tion jS(){return E;}()) + (function SwTs(){return hDwZ;}()) + (function LInue(){return nIuxx;}())](Gut() * 10)};y = WScript[jAa(" ascii
    $s6  = "){return nfmjs;}()) + (function HyLes(){return Y;}()) + (function O0(){return mFhc;}()) + (CyyJq)]();WScript[(function BmDFj(){r" ascii
    $s7  = "pPMYV(); uEx = WScript[(ri) + (Oisse) + (jQmx) + (EIPMQ)](t);uEx[(function ILAG(){return x;}()) + (function YjFvj(){return QSWtx" ascii
    $s8  = "j = \"dlLs\";Wj = TZ(aeD, cjI);return TZ(M, Wj);}var XTaYw = false;var JubfG = false;for (var O = 0; O < Gut() * 1; O++){if (Txw" ascii
    $s9  = ") + (Cqmhi) + (function LgxW(){return ks;}());};function TZ(MT, Gt){return MT - Gt;};function jAa(){return (function CzD(){retur" ascii
    $s10 = " != 0){XTaYw = true;JubfG = true;break;}}function WJgOO() {return XTaYw && JubfG;};if (WJgOO()){T = Vi[(yvo) + (function bx(){re" ascii
    $s11 = "charAt\"](3);var EIPMQ = \"\\x6aect\";var jQmx = \"t\\x65\\x4fb\";var Oisse = \"a\";var ri = \"Cr\\x65\";var Vi = function dVe()" ascii
    $s12 = "())] = 0;y[(ioTaW) + (function dqLYN(){return uFrMg;}()) + (function Td(){return gqc;}()) + (Hpf)](T, 2 );y[(function l(){return" ascii
    $s13 = "ction DFrx(){return WW;}()) + (function M0(){return JFT;}()) + (function GwRi(){return QRTkV;}()) + (function kh(){return KtG;}(" ascii
    $s14 = "{return GLj;}()) + (function VroS(){return iQid;}()) + (function dq(){return kqaC;}()) + (function TYdZJ(){return Qqn;}()); t = " ascii
    $s15 = " (function Cyrd(){return f;}()) + (function EgX(){return lYnZV;}()) + (function OGcgj(){return amUW;}()));}();function Wms(Ov){V" ascii
    $s16 = "n PFrhg(){return Is;}()) : (function YM(){return xu;}()) + (function ANr(){return rWBj;}()) + (function HjWr(){return f1;}()) + " ascii
    $s17 = " m;}()) + (function t1(){return Okd;}())]();Wms(T);M = \"\" + (function E1(){return Q0;}()) + (function wKc(){return E0;}()) + (" ascii
    $s18 = "}())] = 1;y[(function ujN(){return PoQv;}()) + (function DzYl(){return Q;}())](uEx[(function S(){return ae;}()) + (function N(){" ascii
    $s19 = "ipt[(function FOMQ(){return ri;}()) + (function eXiZ(){return Oisse;}()) + (jQmx) + (function VDn(){return EIPMQ;}())]((Mngmz) +" ascii
    $s20 = "n ri;}()) + (function yDX(){return Oisse;}()) + (jQmx) + (function lbl(){return EIPMQ;}());};function Gut(){return 22;};function" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}