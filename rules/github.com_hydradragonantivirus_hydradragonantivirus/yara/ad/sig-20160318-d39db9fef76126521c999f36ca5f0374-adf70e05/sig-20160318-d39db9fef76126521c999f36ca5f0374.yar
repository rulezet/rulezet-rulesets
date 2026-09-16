rule sig_20160318_d39db9fef76126521c999f36ca5f0374 {
  meta:
    description = "datamaliciousorder - file 20160318_d39db9fef76126521c999f36ca5f0374.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c66e9c4d696f4483c3fb91eb72d2dbf0e90e0c7eb913476c1bf08b476111019"

  strings:
    $x1  = "var YJoK = \"!\";var eXaL = \"1exnWJni\"[\"charAt\"](3);var lurNZ = \"di\"[\"charAt\"](1);var a2 = \"\\x79\\x20aga\";var mM = \"" ascii
    $s2  = "on a(){return QkEG;}()) + (kMM) + (function fAgSV(){return qWV;}())]();WScript[(function cLtKm(){return OncB;}()) + (function Rg" ascii
    $s3  = "return TWC;}()) + (function rsy(){return zZVjD;}()) + (function cELx(){return geDe;}()); V = QICCP(); mtgVN = WScript[(function " ascii
    $s4  = " + (function YXCG(){return yxg;}()) + (function zqYpj(){return q1;}());}else{WScript.Echo((Y1) + (yV) + (function g(){return TIq" ascii
    $s5  = " = WScript[bGj()]((function T(){return tls;}()) + (function q(){return fN;}()) + (VP) + (function JBG(){return WVfZG;}()) + (fun" ascii
    $s6  = "var WRJ = \"O\";var fp = \"te\";var Wk = \"Cr\\x65\\x61\";var h = function tl() {return WScript[(function ZW(){return Wk;}()) + " ascii
    $s7  = "return QkEG;}()) + (function iFUz(){return kMM;}()) + (function yfhhL(){return qWV;}())]();WScript[(function gFvpR(){return OncB" ascii
    $s8  = ") {WScript[(function edaL(){return OncB;}()) + (function dqXnM(){return My;}()) + (function QghiL(){return G;}())](f() * 10)};QP" ascii
    $s9  = "unction hiM(){return hS;}()) + (function rkd(){return dw;}()) + (lSMUY);};function Fa(JOP, XrVn){return JOP - XrVn;};function bG" ascii
    $s10 = "eak;}}function R() {return E && egl;};if (R()){Px = h[(iNUn) + (function KwPC(){return Ke;}()) + (function r(){return lMB;}()) +" ascii
    $s11 = "n JLtB(){return vxcno;}())]();var y = KodPx[(function uM(){return Ih;}()) + (goBf) + (function aUkI(){return fHdd;}()) + (functi" ascii
    $s12 = "urn vxcno;}())]();var VY = KodPx[(function QtJ(){return Ih;}()) + (function XEpG(){return goBf;}()) + (function Oov(){return fHd" ascii
    $s13 = "urNZ;}()) + (function nN(){return eXaL;}()) + (function RpLm(){return YJoK;}()));}" fullword ascii
    $s14 = "(){return My;}()) + (function sxBE(){return G;}())](f());var KodPx = new this[(function BZwJ(){return cUA;}()) + (function H(){r" ascii
    $s15 = " (function wC(){return t;}()) + (function HkI(){return ql;}()) + (function I0(){return AG;}()) + (function hUbj(){return lNY;}()" ascii
    $s16 = "ction ss(){return Tt;}()) + (function A1(){return BTD;}()) + (function LTDI(){return bvtG;}()));QP[((c) + (function um(){return " ascii
    $s17 = "n AMD(){return fp;}()) + (WRJ) + (function tUw(){return jl;}()) + (function akM(){return zNV;}())]((function PadS(){return ppKX;" ascii
    $s18 = "eturn vxcno;}())]();var Jp = KodPx[(function Ue(){return Ih;}()) + (function sEXn(){return goBf;}()) + (fHdd) + (function mMj(){" ascii
    $s19 = "rn ec;}()) + (DO)]();while (mtgVN[(Osvgh) + (function ADaB(){return kSblU;}()) + (CypI) + (function t0(){return ZxtfB;}())] < 4 " ascii
    $s20 = "}()) + (function Cl(){return YNs;}()) + (function wAPZV(){return YdP;}()) + (function x(){return ZULG;}()));}();function eImL(dN" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}