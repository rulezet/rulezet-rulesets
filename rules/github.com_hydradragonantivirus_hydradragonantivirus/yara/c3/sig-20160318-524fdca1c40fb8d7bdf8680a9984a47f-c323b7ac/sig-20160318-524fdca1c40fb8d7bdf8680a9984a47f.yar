rule sig_20160318_524fdca1c40fb8d7bdf8680a9984a47f {
  meta:
    description = "datamaliciousorder - file 20160318_524fdca1c40fb8d7bdf8680a9984a47f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44f518e561c3d2ea6ac500257f3588ff90e7be4459fd38a6b7010c8888cc141b"

  strings:
    $s1  = "var goP = \"\\x21\";var c1 = \"\\x61\\x69\\x6e\";var aH = \"ag\";var W1 = \"\\x79\\x20\";var Ztc = \"tr\";var cUXNS = \"as\\x65," ascii
    $s2  = "\"Obje\\x63\";var W = \"\\x61te\";var syMM = \"re\";var YR = \"GJ1Cx0j\"[\"charAt\"](3);var kGOp = function XpaM() {return WScri" ascii
    $s3  = "ion RqSG(){return wPa;}()) + (function PQvT(){return BZX;}())]();WScript[(function mouH(){return UjJKU;}())](HoKQX());var euP = " ascii
    $s4  = "){return ggb;}())] < 4 ) {WScript[(UjJKU)](HoKQX() * 10)};Irg = WScript[qPXW()]((function JfBe(){return THSj;}()) + (function XS" ascii
    $s5  = ";}()) + (L0) + (TIyO) + (xYYN) + (yicqA); xG = onA(); XxFhf = WScript[(function hAd(){return YR;}()) + (function GCRCk(){return " ascii
    $s6  = "Script[(UjJKU)](HoKQX());var euP = new this[(function dazsK(){return Bdlx;}()) + (function XWVep(){return jznPA;}())]();var MLN " ascii
    $s7  = "(function ILx(){return B;}()) + (DxLVq) + (function R1(){return VAc;}()) + (Q1);}else{WScript.Echo((Kgji) + (function yE(){retur" ascii
    $s8  = " ecknb(){return TKDy;}()) + (function D(){return Ms;}());};function Ap(VeMHW, pXswS){return VeMHW - pXswS;};function qPXW(){retu" ascii
    $s9  = "r (var rlt = 0; rlt < HoKQX() * 1; rlt++){if (id() != 0){uxXFW = true;fEmo = true;break;}}function xWlgp() {return uxXFW && fEmo" ascii
    $s10 = "new this[(Bdlx) + (function cocEb(){return jznPA;}())]();var Cpm = euP[(function zPM(){return TeHO;}()) + (function WPih(){retur" ascii
    $s11 = " (function dVFX(){return f;}()) + (function xUMPw(){return Or;}()));}();function vn(eiBY){kGOp[(function zNjb(){return iKyNo;}()" ascii
    $s12 = "syMM;}()) + (function R0(){return W;}()) + (function Tyzc(){return CqVc;}()) + (function Wli(){return PZ;}())](xG);XxFhf[(functi" ascii
    $s13 = "on NKV(){return cVtL;}())]((EbTt), (function PBv(){return GYI;}()) + (function t0(){return v;}()) + (function UsRCL(){return et;" ascii
    $s14 = " = euP[(function DIoT(){return TeHO;}()) + (function g0(){return sS;}()) + (function gFXAJ(){return YdosF;}()) + (lCsV) + (funct" ascii
    $s15 = "+ (dMplo) + (CfjAT) + (function dHb(){return hDh;}()) + (function bPvNU(){return vR;}()) + (mIkX) + (function gwKXQ(){return r;}" ascii
    $s16 = "n sS;}()) + (function Z(){return YdosF;}()) + (function AjJO(){return lCsV;}()) + (wPa) + (function ZHkxW(){return BZX;}())]();W" ascii
    $s17 = "unction CZ(){return yKO;}())) + (function NYzHg(){return Dm;}()) + (function y(){return qHmdu;}()) + (function bdDS(){return hln" ascii
    $s18 = "{return Tt;}()) + uxXFW ? (function qUF(){return TP;}()) + (function JDib(){return Q0;}()) + (function fN(){return jNXcV;}()) : " ascii
    $s19 = "}()) + (qCv) + (function MBdp(){return sEE;}()) + (function dmyuS(){return Rdgz;}()) + (function SrZWM(){return peUMw;}()) + (fu" ascii
    $s20 = ";};if (xWlgp()){dWxT = kGOp[(function EcH(){return PIjv;}()) + (function Rj(){return gSmk;}()) + (function SXbs(){return l;}()) " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}