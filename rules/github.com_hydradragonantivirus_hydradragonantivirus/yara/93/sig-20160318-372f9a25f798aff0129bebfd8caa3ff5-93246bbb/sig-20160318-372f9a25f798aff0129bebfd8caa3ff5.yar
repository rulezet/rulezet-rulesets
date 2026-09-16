rule sig_20160318_372f9a25f798aff0129bebfd8caa3ff5 {
  meta:
    description = "datamaliciousorder - file 20160318_372f9a25f798aff0129bebfd8caa3ff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34d4ab07b3d5d27b99c94449ba86499c55b1bab334fb435efd469942d57d49ab"

  strings:
    $s1  = "var pHzRD = \"Lv!74\"[\"charAt\"](2);var UpGx = \"g\\x61in\";var QIsCB = \"\\x20a\";var TLrK = \"\\x79\";var nhlS = \"r\";var zU" ascii
    $s2  = " (PqT) : (function uTmj(){return vnY;}()) + (function RB(){return AD;}()) + (function ImVkr(){return GYGF;}());}else{WScript.Ech" ascii
    $s3  = ") * 10)};S = WScript[hmp()]((function Il(){return ph;}()) + (function PBTE(){return QaR;}()) + (gAlYt));S[((function PeK(){retur" ascii
    $s4  = " WaC(){return pwHQc;}()) + (function b(){return PhA;}()) + (function lbjX(){return Qr;}())]();WScript[(function lPZ(){return YbE" ascii
    $s5  = "eturn PhA;}()) + (function D(){return Qr;}())]();WScript[(YbE) + (function Wdg(){return BKbpo;}())](Vx());var ivNd = new this[(f" ascii
    $s6  = "wpV;}()) + (function On(){return dUk;}())] < 4 ) {WScript[(function oY(){return YbE;}()) + (function ia(){return BKbpo;}())](Vx(" ascii
    $s7  = "turn C;}()) + (function B(){return m0;}()) + (function XA(){return HevqD;}());};function oM(HicZG, sor){return HicZG - sor;};fun" ascii
    $s8  = "{return yXWu && Zz;};if (ZdQ()){XP = MDob[(function MXF(){return MAevN;}()) + (function r(){return wrl;}()) + (CdCsy) + (functio" ascii
    $s9  = "){return knBv;}()) + (HPZ); m = FLGCa(); lQ = WScript[(t) + (function MOhiY(){return W;}()) + (function LJ(){return p;}()) + (fu" ascii
    $s10 = " = ivNd[(function fElW(){return AYk;}()) + (function WBgA(){return S0;}()) + (function ys(){return pwHQc;}()) + (function Nb(){r" ascii
    $s11 = "unction ulfVQ(){return AYk;}()) + (S0) + (function YLCqh(){return pwHQc;}()) + (function nFHsN(){return PhA;}()) + (function pqU" ascii
    $s12 = "n mCcd(){return Mf;}()) + (function V(){return qWDJ;}()) + (function Q0(){return jw;}()) + (function J(){return xnVz;}()) + (fCm" ascii
    $s13 = ";}()) + (function AHXrW(){return BKbpo;}())](Vx());var ivNd = new this[(function oDpZ(){return StCZK;}())]();var FMDNm = ivNd[(f" ascii
    $s14 = "n sHId(){return RX;}()) + (function mi(){return MYbYK;}()) + (function p1(){return P0;}()) + (function EJHxh(){return IuW;}()) +" ascii
    $s15 = "urn lLTo;}()) + (function znxo(){return VpiPs;}()) + (function JK(){return Qz;}()) + (function Usbpu(){return mP;}()) + (functio" ascii
    $s16 = "(function H(){return QCWZ;}()) + (function IsDKf(){return ulALL;}()) + (function jf(){return TnXAz;}()) + (fL) + yXWu ? (functio" ascii
    $s17 = "unction IjixO(){return StCZK;}())]();var ffTx = ivNd[(function JGC(){return AYk;}()) + (function C0(){return S0;}()) + (function" ascii
    $s18 = "){return NtRaF;}()) + (function SDT(){return pOR;}()) + (tH) + (function qstLq(){return P;}()));}();function hhvy(Wl){MDob[(func" ascii
    $s19 = "ction hmp(){return (function LaHcx(){return t;}()) + (function IyZM(){return W;}()) + (function MoSG(){return p;}()) + (function" ascii
    $s20 = "o((function qkfp(){return VMSgc;}()) + (mUn) + (function OEw(){return zU;}()) + (function NYJn(){return nhlS;}()) + (function RD" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}