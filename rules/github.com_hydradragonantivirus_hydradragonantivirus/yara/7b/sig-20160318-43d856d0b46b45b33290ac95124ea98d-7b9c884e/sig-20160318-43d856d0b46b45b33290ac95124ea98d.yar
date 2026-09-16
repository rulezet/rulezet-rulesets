rule sig_20160318_43d856d0b46b45b33290ac95124ea98d {
  meta:
    description = "datamaliciousorder - file 20160318_43d856d0b46b45b33290ac95124ea98d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fea66c9039776f7cf9b61331f792a9c66741f2ceac9850c0d47a89441374f432"

  strings:
    $x1  = "var ubYI = \"Nyz!\"[\"charAt\"](3);var xgGu = \"ag\\x61\\x69\\x6e\";var kTnUs = \"\\x72y \";var dQ = \"e\\x2c\\x20\\x74\";var oj" ascii
    $s2  = "rn hIdp;}()) + (function s1(){return m;}()) + (function pOuO(){return BjP;}())]();WScript[(function LgG(){return VtsBG;}())](pl(" ascii
    $s3  = "(function m0(){return KG;}()); SWgKc = MqGBt(); Rin = WScript[(function Cr(){return nX;}()) + (g) + (function WRUO(){return ozn;" ascii
    $s4  = "t[(function M(){return VtsBG;}())](pl() * 10)};qbiTr = WScript[pA()]((function QdCUN(){return uMJx;}()) + (jRGa) + (function DEu" ascii
    $s5  = "v(){return AiZ;}()) + (function rGuS(){return FCrd;}());}else{WScript.Echo((YiCwZ) + (function Ft(){return ojo;}()) + (function " ascii
    $s6  = "Cr\";var vMWT = function qpNU() {return WScript[(function RSlct(){return nX;}()) + (function QX(){return g;}()) + (function ofs(" ascii
    $s7  = "on kVBV(){return hIdp;}()) + (function tk(){return m;}()) + (function FWBW(){return BjP;}())]();WScript[(function ymo(){return V" ascii
    $s8  = "return kIZr;}())]();var MxEbK = fZJEe[(function RUjw(){return nGtO;}()) + (function oy(){return lHV;}()) + (function mDLl(){retu" ascii
    $s9  = " - fzpD;};function pA(){return (function zvrkB(){return nX;}()) + (g) + (function gWVjc(){return ozn;}()) + (function DvvDY(){re" ascii
    $s10 = "() * 1; Rlj++){if (R() != 0){NKS = true;pavK = true;break;}}function GuUgk() {return NKS && pavK;};if (GuUgk()){FjvR = vMWT[(fun" ascii
    $s11 = "RvF) + (function tziu(){return whC;}()) + (function wcB(){return gD;}()) + (function AN(){return uwI;}()) + (function aGLJ(){ret" ascii
    $s12 = "));var fZJEe = new this[(kIZr)]();var dKwCT = fZJEe[(function Y(){return nGtO;}()) + (function sDvDA(){return lHV;}()) + (functi" ascii
    $s13 = "A;}()) + (function kde(){return XsfAY;}()) + (function tZ(){return RaCf;}()) + (FChs) + (j) + (function xtQ(){return wC;}()) + (" ascii
    $s14 = "return IT;}()) + (hxrf) + (function J(){return H;}()) + (function TbtN(){return FFCk;}());};function s(miGJP, fzpD){return miGJP" ascii
    $s15 = "{return ozn;}()) + (function yJwn(){return ZauS;}()) + (function VT(){return B;}())]((g0) + (function b0(){return eWjj;}()) + (f" ascii
    $s16 = "n b(BcH){vMWT[(function S(){return P;}()) + (function E(){return yHE;}())](BcH, 0, 0);};function MqGBt(){return (function VEj(){" ascii
    $s17 = "urn qxHa;}()) + (function oz(){return O0;}())]((function i(){return yM;}()) + (function OoKqY(){return EpgQT;}())) + (function k" ascii
    $s18 = "z) + (function nVst(){return n;}())]);qbiTr[(function Z(){return Txdug;}()) + (function t0(){return UfFIf;}()) + (function hDGtV" ascii
    $s19 = "ction Du(){return SfO;}()) + (function o0(){return sE;}()) + (function vBUg(){return gadA;}()) + (function xPR(){return RzWFU;}(" ascii
    $s20 = "(){return RmCqm;}())](Rin[(function A0(){return B0;}()) + (function iG(){return vORz;}()) + (function ew(){return I;}()) + (euyu" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}