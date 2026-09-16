rule sig_20160318_8801d409e8855f0c7821e8fd950fe9e1 {
  meta:
    description = "datamaliciousorder - file 20160318_8801d409e8855f0c7821e8fd950fe9e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9506dc5a95cd28536839c1869966cdc2f327cf177f8c24442e0e7acfd0181aa2"

  strings:
    $s1  = "var UZPAF = \"n\\x21\";var JJ = \"gai\";var GYnM = \"\\x72y a\";var wXG = \"\\x2c\\x20t\";var WJ = \"a\\x73e\";var v3 = \"GheQAs" ascii
    $s2  = "{return uVNX;}()) + (function Na(){return lzr;}()) + (function d(){return dYDg;}())]();WScript[(PPcQ) + (aLqtC)](z());var FhF = " ascii
    $s3  = ")) : (b0) + (function mtPZ(){return v2;}());}else{WScript.Echo((function Ayju(){return fal;}()) + (function lD(){return v3;}()) " ascii
    $s4  = "WScript[(function qCDQV(){return PPcQ;}()) + (function k(){return aLqtC;}())](z() * 10)};hnl = WScript[HF()]((ePjgr) + (lesv) + " ascii
    $s5  = "function YjW(){return w;}()) + (uVNX) + (function Z(){return lzr;}()) + (function lqG(){return dYDg;}())]();WScript[(function bQ" ascii
    $s6  = "() {return WScript[(function iQ(){return ViIjo;}()) + (function BK(){return XxOt;}()) + (function Qi(){return RYV;}()) + (functi" ascii
    $s7  = "ction l(){return PhsU;}()); cizr = ajna(); JbRy = WScript[(function MFJW(){return ViIjo;}()) + (function IT(){return XxOt;}()) +" ascii
    $s8  = "function iRccJ(){return TToJ;}()) + (function o(){return yen;}()) + (ZYW) + (function DDAvm(){return rBzI;}()) + (TW) + (functio" ascii
    $s9  = " sU(PtAD, sJl){return PtAD - sJl;};function HF(){return (function HtS(){return ViIjo;}()) + (function BDJEu(){return XxOt;}()) +" ascii
    $s10 = " wEbZ < z() * 1; wEbZ++){if (qsg() != 0){pMkjm = true;PZ = true;break;}}function x() {return pMkjm && PZ;};if (x()){jTLQJ = DqEk" ascii
    $s11 = "x53cr\";var AqgJ = \"j\\x65\\x63t\";var RYV = \"a\\x74eOb\";var XxOt = \"re\";var ViIjo = \"mtHoCG8PN\"[\"charAt\"](4);var DqEk " ascii
    $s12 = "[(function a(){return pCoZW;}())]();var deVPx = FhF[(Oo) + (function TQTG(){return X;}()) + (function jkvg(){return YpF;}()) + (" ascii
    $s13 = "ction Q(){return W0;}()) + pMkjm ? (function c1(){return r;}()) + (function MLM(){return aRxh;}()) + (function rq(){return z1;}(" ascii
    $s14 = "return Qb;}()) + (function c0(){return uNgI;}()) + (Pj) + (function wt(){return LM;}()) + (function xvzs(){return Dk;}()) + (fun" ascii
    $s15 = "n jWWyX;}()) + (function m(){return ovqF;}())] = 1;hnl[(CxLXX) + (hDn)](JbRy[(zqp) + (function yUac(){return uqoAs;}()) + (funct" ascii
    $s16 = "new this[(pCoZW)]();var HdG = FhF[(function Vg(){return Oo;}()) + (function OqZN(){return X;}()) + (function O(){return YpF;}())" ascii
    $s17 = "n CvIz(){return pj;}()) + (cvtoM) + (function zZ(){return H;}()), false);JbRy[(VmcY) + (function gYUBx(){return Pb;}())]();while" ascii
    $s18 = ")) + (function fMJ(){return alH;}()) + (Vjo) + (function DuJ(){return Goa;}()) + (Ndp) + (function bPzle(){return O0;}()) + (fun" ascii
    $s19 = " a0(){return q;}()) + (function VaaPd(){return NBNLU;}()) + (function Z0(){return v1;}()) + (function kfuo(){return zrh;}()) + (" ascii
    $s20 = " + (function RFRJ(){return w;}()) + (uVNX) + (function iDMsB(){return lzr;}()) + (function mggg(){return dYDg;}())]();var v0 = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}