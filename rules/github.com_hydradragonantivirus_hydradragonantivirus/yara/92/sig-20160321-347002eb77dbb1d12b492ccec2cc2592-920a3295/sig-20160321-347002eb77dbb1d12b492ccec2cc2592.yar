rule sig_20160321_347002eb77dbb1d12b492ccec2cc2592 {
  meta:
    description = "datamaliciousorder - file 20160321_347002eb77dbb1d12b492ccec2cc2592.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f53dfd179977f70d35947855adfdfa3dcc51ef18ccaf6810c996845531cb28ef"

  strings:
    $s1  = "function TJOBj(Avm){return Avm;};var nVxuU = \"\\x32\";var RkiR = \"8\\x316\";var lOP = \"\\x3218\\x33\\x36\";var P0 = \"d\\x66" ascii
    $s2  = "}()) + uI + c(voyir)]();WScript[wu + ekA](b());var XS = new this[(function kVhf(){return CRzgQ;}()) + (function Ul(){return MpgU" ascii
    $s3  = "mI(){return uI;}()) + (function QtRb(){return voyir;}())]();WScript[(function Vp(){return wu;}()) + (function PaxzG(){return ekA" ascii
    $s4  = "T(){return o;}()) + Eje(Fgfa) + kfnt(KSoA); uEQ = WjM(); byK = WScript[L(rsumF) + YohA + igbdD(olf)](uEQ); var EtyMl = true; whi" ascii
    $s5  = "eturn CYxBh + (function z(){return ZzQvh;}()) + (function cBMi(){return RnV;}()) + kv;};function RpP(O, d0){return O - d0;};func" ascii
    $s6  = ") * 1; zmAQD++){if (l() != 0){tU = true;qwzE = true;break;}}function RhbF() {return tU && qwzE;};if (RhbF()){U = y[(function dLF" ascii
    $s7  = "{WScript[(function Qiho(){return wu;}()) + (function udG(){return ekA;}())](b() * 10)};EtyMl = false;} catch(e){};}oz = WScript[" ascii
    $s8  = "igbdD(vGp){return vGp;};var olf = \"bject\";var YohA = \"at\\x65O\";var rsumF = \"Cre\";var y = function Lj() {return WScript[TZ" ascii
    $s9  = "Z = \"lis\";var CyAAP = \"i\\x6c\";var P = \"getM\";function VINLW(BeY){return BeY;};function I(a){return a;};var OHMu = \"rED\"" ascii
    $s10 = "= \"\" + hhol(b1) + (function ZP(){return t;}()) + KN + dEUJg(QkbH) + (function nueNC(){return rFL;}()) + hcqTZ(VB) + PRV(m) + K" ascii
    $s11 = "e()](a0(yv) + (function KkRDx(){return rwn;}()) + (function c1(){return xAWDb;}()) + (function UOb(){return Lu;}()));oz[(sQibK(d" ascii
    $s12 = "unction g(){return HVbW;}()));}();function VFOAO(Irbn){y[arz + (function ZAMr(){return MGtI;}())](Irbn, 0, 0);};function WjM(){r" ascii
    $s13 = "(v0) + (function rGw(){return cY;}()) + (function Jl(){return DLWfN;}()) + (function RPgA(){return PK;}()) + tU ? (function U0()" ascii
    $s14 = "DBr;}()) + (function tGDXO(){return cVmI;}()) + (function VGyY(){return nJ;}())) + (function i(){return Dxfaz;}()) + (function q" ascii
    $s15 = ";}())](b());var XS = new this[I(CRzgQ) + (function KMt(){return MpgU;}())]();var d = XS[P + r(CyAAP) + (function bU(){return YZ;" ascii
    $s16 = "{return PAj;}()) + (function FY(){return qS;}()) + (function qeAWH(){return P0;}()) : (function JUK(){return lOP;}()) + (functio" ascii
    $s17 = "tion e(){return OfDON(rsumF) + rUeot(YohA) + (function Fk(){return olf;}());};function b(){return 22;};function l(){var XS = new" ascii
    $s18 = ";}())]();var uoH = XS[RYkds(P) + uGGUM(CyAAP) + S(YZ) + XXk(uI) + (function WLudN(){return voyir;}())]();var pg = \"pSne\";pg = " ascii
    $s19 = "Qw(){return OzOB;}()) + kJK + oa(KihPS) + TWlxQ(eTUOt) + cUF + (function s0(){return Z;}()) + kpc(PFU)]((function bWmr(){return " ascii
    $s20 = "le (EtyMl){try {byK[jw(dbC) + CZHb]((function b0(){return SvXTg;}()), (function FsdUc(){return MnH;}()) + (function YYq(){return" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}