rule sig_20160318_5aba03f885bef35d0328d0f20a522977 {
  meta:
    description = "datamaliciousorder - file 20160318_5aba03f885bef35d0328d0f20a522977.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f25b605d8eaca04b2e72fb3e374c05818811ead1fa2641e23c6f3bec9852538b"

  strings:
    $s1  = "var pSno = \"\\x21\";var Bte = \"i\\x6e\";var M0 = \" a\\x67a\";var iw = \" try\";var Ikx = \"Kf,\"[\"charAt\"](2);var TWugy = " ascii
    $s2  = "function LYKV(){return EqoRP;}()) + (function T0(){return KnI;}()) + (function lzLyk(){return oH;}());}else{WScript.Echo((NxSb) " ascii
    $s3  = "SLbW(){return CV;}()) + (function WfMY(){return Qse;}()) + (function ekKig(){return jD;}()) + (kkxT)]();WScript[(FQ0) + (functio" ascii
    $s4  = "gNE(); P = WScript[(function aMVd(){return fCP;}()) + (function b(){return Tp;}()) + (function m(){return vMO;}())](bNs);P[(func" ascii
    $s5  = "(D0)](VeN() * 10)};ixP = WScript[HZQn()]((function KZnK(){return l;}()) + (function cy(){return JkFKC;}()) + (function tdHPf(){r" ascii
    $s6  = "var Tp = \"e\\x4f\\x62j\";var fCP = \"\\x43reat\";var mwrI = function lJcjw() {return WScript[(function Ijk(){return fCP;}()) + " ascii
    $s7  = "){return x0;}())]();while (P[(function E0(){return Ctify;}()) + (HbM) + (function Vc(){return XekU;}())] < 4 ) {WScript[(FQ0) + " ascii
    $s8  = "nction w(Zd, souVq){return Zd - souVq;};function HZQn(){return (function C(){return fCP;}()) + (function yHc(){return Tp;}()) + " ascii
    $s9  = " VeN() * 1; FhJXP++){if (jj() != 0){RwUc = true;anyvM = true;break;}}function XBa() {return RwUc && anyvM;};if (XBa()){zlPX = mw" ascii
    $s10 = "70\\x65\";var DHD = \"HX1n\"[\"charAt\"](3);var sAgzY = \"ope\";var q = \"cmGtuW4\"[\"charAt\"](1);var UIcSc = \"a\";var WTp = " ascii
    $s11 = "ction w0(){return Cjmfn;}()) + (function t(){return Wd;}()))]();ixP[(DE)] = 1;ixP[(function Vszm(){return Ji;}()) + (function Vi" ascii
    $s12 = "unction Z(){return PwA;}())]();var yrfM = mO[(function sW(){return tPmj;}()) + (function JBOC(){return yK;}()) + (CV) + (functio" ascii
    $s13 = "()) + (function SyStM(){return s0;}())) + (function R(){return ZF;}()) + (function ovpBB(){return eWwd;}()) + (function PfNH(){r" ascii
    $s14 = "eturn ose;}()) + (function Q(){return WTp;}()) + (function dUXpr(){return UIcSc;}()) + (function JBJA(){return q;}()));ixP[((fun" ascii
    $s15 = " + (function ffE(){return fy;}()) + (function Wc(){return D2;}()) + (function nNkgu(){return Yb;}()) + (function M(){return gBE;" ascii
    $s16 = " (function DqEXw(){return PwA;}())]();var VRV = mO[(function fn(){return tPmj;}()) + (function eW(){return yK;}()) + (function q" ascii
    $s17 = "oS;}()) + (cl) + (function jAdL(){return eVe;}()) + (function MFSUt(){return ahjH;}()) + (jMBzm), false);P[(N0) + (function aIq(" ascii
    $s18 = "ript[(function bOuH(){return FQ0;}()) + (function sF(){return D0;}())](VeN());var mO = new this[(function N(){return a;}()) + (f" ascii
    $s19 = ";}()) + (function OJpL(){return Bn;}()) + (function gOUDv(){return jA;}()) + RwUc ? (function kyKX(){return XKsy;}()) + (ES) : (" ascii
    $s20 = "+ (function s1(){return TWugy;}()) + (function hlZvM(){return Ikx;}()) + (function j0(){return iw;}()) + (function MOYTR(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}