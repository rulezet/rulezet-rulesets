rule sig_20160318_6c924cd9a9c41f759a2e899b52dd08d0 {
  meta:
    description = "datamaliciousorder - file 20160318_6c924cd9a9c41f759a2e899b52dd08d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50a568b6d7ca28f995f9d0eb934490ed582543cd092ead222fb4029693bc56de"

  strings:
    $x1  = "var aN = \"X!\"[\"charAt\"](1);var UFztB = \"\\x6e\";var gG = \"g\\x61i\";var FAcP = \"\\x79 a\";var J1 = \"\\x65\\x2c tr\";var " ascii
    $s2  = "r jS = \"\\x61t\\x65\";var A = \"Cre\";var Eq = function Rm() {return WScript[(function GV(){return A;}()) + (function H(){retur" ascii
    $s3  = "(function beB(){return eLfD;}()) + (function W(){return Gup;}()) + (RXcZt); t = GOugk(); ZpgY = WScript[(function DD(){return A;" ascii
    $s4  = "k;}());}else{WScript.Echo((function tGN(){return sK;}()) + (vOjU) + (J1) + (FAcP) + (gG) + (UFztB) + (aN));}" fullword ascii
    $s5  = "}())]();WScript[(function zwCWc(){return ivcw;}()) + (function YlP(){return dC;}())](QTEI());var Ncl = new this[(NxwcZ) + (XCY)]" ascii
    $s6  = "on o0(){return FhUH;}())] < 4 ) {WScript[(function RiLB(){return ivcw;}()) + (function Jo(){return dC;}())](QTEI() * 10)};CcN = " ascii
    $s7  = "WScript[b()]((W1) + (function aK(){return n2;}()) + (Pwb) + (function BLi(){return flj;}()) + (function lfIA(){return cq;}()));C" ascii
    $s8  = "ction F(zTtt, Mdv){return zTtt - Mdv;};function b(){return (function KhY(){return A;}()) + (function HJ(){return jS;}()) + (func" ascii
    $s9  = " < QTEI() * 1; Mf++){if (a() != 0){PS = true;fOx = true;break;}}function J() {return PS && fOx;};if (J()){y = Eq[(function C(){r" ascii
    $s10 = "ction Oe(){return oM;}()));}();function hrHe(AgDFg){Eq[(function eWBN(){return mso;}()) + (McgQ)](AgDFg, 0, 0);};function GOugk(" ascii
    $s11 = "pt[(function XPP(){return ivcw;}()) + (function N(){return dC;}())](QTEI());var Ncl = new this[(NxwcZ) + (function LSn(){return " ascii
    $s12 = " \"\" + (s) + (function xOd(){return yA;}()) + (function LyGiq(){return z0;}()) + (function hgcPh(){return ujtC;}()) + (function" ascii
    $s13 = "()) + (n) + (function ZqScv(){return o;}())]((function ZCjN(){return VR;}()) + (xiUkb) + (function Fw(){return BXBcr;}()) + (fun" ascii
    $s14 = "qSnr(){return JLxax;}()) + (function hHzij(){return afZGs;}()) + (Ud)] = 0;CcN[(function ubHD(){return Rgi;}()) + (function ppn(" ascii
    $s15 = "P(){return ioCU;}()) + (function AJA(){return B0;}()) + (function IkhLi(){return nbdkb;}()) + (function aa(){return x;}())]((fun" ascii
    $s16 = "){return (function n0(){return Lk;}()) + (L) + (VwXH) + (function xHFxN(){return WUg;}()) + (function Cd(){return Asl;}());};fun" ascii
    $s17 = "cN[((function Wyl(){return UQXe;}()) + (function SVu(){return E;}()))]();CcN[(function KX(){return eKt;}())] = 1;CcN[(function Y" ascii
    $s18 = "XCY;}())]();var mhQ = Ncl[(RIcH) + (function Wy(){return j;}()) + (function q(){return PIi;}()) + (function MpGr(){return T;}())" ascii
    $s19 = "ction Y0(){return nx;}()) + (function fcg(){return BF;}()) + (function pMC(){return Dqg;}())) + (function BJ(){return Mn;}()) + " ascii
    $s20 = " YV;}()) + (function LpBE(){return EYBV;}()) + (function JAQR(){return hz;}()) + (function DnB(){return vZ;}())]);CcN[(function " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}