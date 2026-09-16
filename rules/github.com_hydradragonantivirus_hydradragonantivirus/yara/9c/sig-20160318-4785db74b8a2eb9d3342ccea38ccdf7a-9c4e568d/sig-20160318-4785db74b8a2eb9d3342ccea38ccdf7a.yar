rule sig_20160318_4785db74b8a2eb9d3342ccea38ccdf7a {
  meta:
    description = "datamaliciousorder - file 20160318_4785db74b8a2eb9d3342ccea38ccdf7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb086a3b82bc9c96cf961292811c15ff2cc84b3a6fe542d520142d584308947"

  strings:
    $s1  = "var xFNKj = \"in\\x21\";var yAZ = \"ga\";var rCv = \"ry\\x20a\";var wxmdT = \",\\x20t\";var qwcPr = \"e\";var K1 = \"\\x50\\x6c" ascii
    $s2  = "r cHW = \"re\";var POK = \"C\"[\"charAt\"](0);var h = function g() {return WScript[(function PN(){return POK;}()) + (function iE" ascii
    $s3  = "turn rb;}()) + (yxMB); glt = VkK(); suA = WScript[(function QnRP(){return POK;}()) + (function TEN(){return cHW;}()) + (function" ascii
    $s4  = "urn HWE;}()) + (function tIJfo(){return d;}()) + (function W(){return K;}()) + (PwI)]();WScript[(function PVRSs(){return d0;}())" ascii
    $s5  = "urn DxcbR;}()) + (function YBzJ(){return nE;}())] < 4 ) {WScript[(d0) + (function sgaE(){return r0;}())](J() * 10)};NoiU = WScri" ascii
    $s6  = " QAYob;}());}else{WScript.Echo((K1) + (qwcPr) + (function YVBzk(){return wxmdT;}()) + (function mEC(){return rCv;}()) + (yAZ) + " ascii
    $s7  = "tion wh(){return K;}()) + (function DbZ(){return PwI;}())]();WScript[(d0) + (function E(){return r0;}())](J());var eMfX = new th" ascii
    $s8  = "A(Blm, zhWms){return Blm - zhWms;};function cLiVe(){return (function DMVCl(){return POK;}()) + (function V(){return cHW;}()) + (" ascii
    $s9  = "e;for (var sjXd = 0; sjXd < J() * 1; sjXd++){if (XMFyp() != 0){Sqt = true;sYJ = true;break;}}function TMkip() {return Sqt && sYJ" ascii
    $s10 = "ion Ugfte(){return g0;}()), (UItR) + (Pb) + (function GoCjD(){return c0;}()) + (function v0(){return u;}()) + (function FFM(){re" ascii
    $s11 = "))](suA[(O0) + (function SxqA(){return sIZxh;}()) + (hxTfS) + (function w(){return ktz;}())]);NoiU[(function gQ(){return ZRjT;}(" ascii
    $s12 = " + (function igay(){return Y;}()) + (function s(){return IWVrp;}()) + (c) + (function l(){return X1;}()) + (function M(){return " ascii
    $s13 = ";var jBrLv = eMfX[(function lRI(){return BK;}()) + (z) + (function a0(){return HWE;}()) + (function mpvR(){return d;}()) + (func" ascii
    $s14 = "os;}()) + (function ePE(){return Cv;}()) + (Afvfq)]((function oG(){return NxPQL;}()) + (rtT)) + (function qrNao(){return jc;}())" ascii
    $s15 = "is[(function Ddxs(){return as;}()) + (function Ij(){return Dv;}()) + (function MFHY(){return Z;}())]();var yoL = eMfX[(function " ascii
    $s16 = " + (function Ef(){return r0;}())](J());var eMfX = new this[(function n(){return as;}()) + (Dv) + (function D0(){return Z;}())]()" ascii
    $s17 = "function Yec(){return oIl;}()) + (function tJK(){return f;}()) + (function ECWOy(){return D;}());};function J(){return 22;};func" ascii
    $s18 = "function OEN(){return V0;}())]();Zpnu(uH);t = \"\" + (z0) + (function wci(){return w1;}()) + (qmmym) + (hOq) + (function wn(){re" ascii
    $s19 = "rn R0;}()) + (NE), false);suA[(function ZubRP(){return in0;}())]();while (suA[(function Z0(){return k;}()) + (function DvL(){ret" ascii
    $s20 = "pt[cLiVe()]((function YHFPY(){return MIo;}()) + (function Km(){return bDTw;}()) + (y0) + (JSB));NoiU[((function CVoqH(){return d" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}