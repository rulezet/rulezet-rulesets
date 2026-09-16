rule sig_20160318_ee67129f70c29b459644602eadf3ddc1 {
  meta:
    description = "datamaliciousorder - file 20160318_ee67129f70c29b459644602eadf3ddc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5531ec2df0b61fd5bccaf0f0e2afe444214188cbb2406c2a4701f3bf706af25"

  strings:
    $s1  = "var mmagH = \"\\x21\";var cfmfA = \"\\x69\\x6e\";var bhn = \"\\x67a\";var hSgh = \"\\x72y a\";var pX = \"e, \\x74\";var uKvA = " ascii
    $s2  = " + (function r(){return DTzz;}()) + (function I(){return YS;}()) + (function LBptn(){return vk;}())] < 4 ) {WScript[(function Ws" ascii
    $s3  = " function b() {return WScript[(function kx(){return LnC;}()) + (SQeyn) + (YGz) + (function n(){return Ip;}()) + (function jw(){r" ascii
    $s4  = "ion K1(){return dtrE;}()) : (function uBGZq(){return Pwy;}()) + (nXH);}else{WScript.Echo((function Iol(){return yChzU;}()) + (fu" ascii
    $s5  = ")) + (RoFzC) + (function z(){return HWSt;}()) + (function mVEu(){return kOZU;}()) + (function Bty(){return uPNM;}())]();WScript[" ascii
    $s6  = "(){return LQDjx;}())](zcdZ() * 10)};Bj = WScript[qkOQa()]((ecDa) + (function K0(){return A;}()) + (function sWRv(){return Mm;}()" ascii
    $s7  = "}()) + (SO) + (S); vsfJE = Ge(); uFGfC = WScript[(LnC) + (SQeyn) + (YGz) + (function jcq(){return Ip;}()) + (function gv(){retur" ascii
    $s8  = "urn X0;}());};function DC(mOc, gAfEx){return mOc - gAfEx;};function qkOQa(){return (function X(){return LnC;}()) + (function swS" ascii
    $s9  = "rue;lIJo = true;break;}}function Vi() {return CVL && lIJo;};if (Vi()){OxbD = EDHl[(u) + (function XEq(){return Lz;}()) + (Qrl) +" ascii
    $s10 = "function wo(Ly){EDHl[(function Q(){return a;}())](Ly, 0, 0);};function Ge(){return (function R(){return eegER;}()) + (function R" ascii
    $s11 = ";return DC(ZIg, Wzlq);}var CVL = false;var lIJo = false;for (var HdEng = 0; HdEng < zcdZ() * 1; HdEng++){if (wzs() != 0){CVL = t" ascii
    $s12 = "ion N1(){return bL;}()) + (function iOk(){return ATO;}()) + (IqTQ) + (function IZB(){return MMvz;}()) + (function W(){return fZ;" ascii
    $s13 = ") + (function DsCCs(){return z0;}()));Bj[((function qhxtZ(){return rcLOb;}()) + (function nbew(){return pwe;}()))]();Bj[(functio" ascii
    $s14 = "(){return SQeyn;}()) + (YGz) + (Ip) + (function Nkse(){return RDQnF;}());};function zcdZ(){return 22;};function wzs(){var qHF = " ascii
    $s15 = "n RDQnF;}())](vsfJE);uFGfC[(rcLOb) + (function SO0(){return pwe;}())]((function n0(){return Qm;}()), (function xh(){return VAg;}" ascii
    $s16 = "}()) + (function IanS(){return dF;}())]();var phl = qHF[(function IzI(){return T0;}()) + (RoFzC) + (function DAH(){return HWSt;}" ascii
    $s17 = "()) + (function NQMP(){return Fq;}()) + (function xcjmM(){return kT;}()) + CVL ? (function YZc(){return lQu;}()) + (f1) + (funct" ascii
    $s18 = "(LQDjx)](zcdZ());var qHF = new this[(oK) + (function T(){return fFyoL;}()) + (function kBa(){return dF;}())]();var nFQY = qHF[(f" ascii
    $s19 = "()) + (kOZU) + (function EmJ(){return uPNM;}())]();var ZIg = \"jbn\";ZIg = DC(nFQY, kCsja);var Wzlq = \"sBkaZ\";Wzlq = DC(phl, n" ascii
    $s20 = "()) + (function mscn(){return S0;}()) + (function Vj(){return OEI;}()) + (function pwlO(){return vYQK;}()) + (Rf) + (function Vw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}