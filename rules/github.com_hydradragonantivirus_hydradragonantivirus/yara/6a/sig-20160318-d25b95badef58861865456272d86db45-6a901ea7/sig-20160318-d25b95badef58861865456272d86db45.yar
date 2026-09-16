rule sig_20160318_d25b95badef58861865456272d86db45 {
  meta:
    description = "datamaliciousorder - file 20160318_d25b95badef58861865456272d86db45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1451c0181f9043d8aac03e2bb5a2ec7e8d425cd2edc458aa286052b78687d03a"

  strings:
    $s1  = "var vBQPG = \"in!\";var lZvh = \"\\x20\\x61ga\";var Bn = \"m1yHu\"[\"charAt\"](2);var zNpFk = \", \\x74r\";var mfZI = \"le\\x61s" ascii
    $s2  = "u0;}()) + (function csnI(){return PJjKu;}()) : (TFth) + (BDv) + (function HQt(){return rF;}());}else{WScript.Echo((function l0()" ascii
    $s3  = ") {return WScript[(function OKo(){return AEL;}()) + (function iPPnP(){return hZIzq;}()) + (nENt) + (function zSXm(){return QxZj;" ascii
    $s4  = "(){return wbCFD;}())](P() * 10)};l = WScript[yZR()]((function H(){return Yh;}()) + (function AQKg(){return i;}()) + (function fI" ascii
    $s5  = "ction Ifew(){return QW;}()) + (function C(){return oBGWr;}()) + (function FNVeH(){return cl;}())] < 4 ) {WScript[(function ZLTJi" ascii
    $s6  = "function e(){return oE;}()) + (function hE(){return WicKg;}())]();WScript[(function skbmI(){return wbCFD;}())](P());var o = new " ascii
    $s7  = "0;}()); w = OvrK(); FpY = WScript[(AEL) + (function uY(){return hZIzq;}()) + (function fQDT(){return nENt;}()) + (function prD()" ascii
    $s8  = "){return j;}()) + (wtRV) + (function Laj(){return QKO;}());};function HNig(P0, p){return P0 - p;};function yZR(){return (AEL) + " ascii
    $s9  = "e;GTnk = true;break;}}function PDQkX() {return F && GTnk;};if (PDQkX()){Xgwf = FO[(function VSuO(){return B;}()) + (function jGv" ascii
    $s10 = "n Lrzzs(){return WicKg;}())]();WScript[(wbCFD)](P());var o = new this[(function TcbqR(){return cYNsr;}())]();var M = o[(function" ascii
    $s11 = " \"\\x57S\";var QxZj = \"je\\x63t\";var nENt = \"Ob\";var hZIzq = \"7e3E20X\"[\"charAt\"](1);var AEL = \"C\\x72\\x65at\";var FO " ascii
    $s12 = "dGXHm = \"\\x648f\";var loda = \"\\x75\\x37\\x68gs\";var SNIp = \"taB8C\"[\"charAt\"](1);var TJx = \"\\x6fs\\x64f\";var FwO = \"" ascii
    $s13 = "}())]((function wSX(){return cdH;}()) + (function PJCdh(){return N;}()) + (function Ht(){return Wg;}()) + (function Khx(){return" ascii
    $s14 = " RfOUP(){return NfO;}()) + (function kTHw(){return t;}()) + (function Fr(){return ou;}()) + (function bEj(){return UPZR;}()) + (" ascii
    $s15 = "this[(function bDAw(){return cYNsr;}())]();var PtMTW = o[(function uzT(){return NfO;}()) + (function rEUy(){return t;}()) + (ou)" ascii
    $s16 = "), (Dfjc) + (function jIiFa(){return pLUaJ;}()) + (function AwX(){return b0;}()) + (Hs) + (HZKks) + (function FR(){return XDd;}(" ascii
    $s17 = "XHm;}()) + (poC) + (function F1(){return SP;}()) + (function bNrHy(){return n0;}()) + (function o1(){return URDJ;}()) + (functio" ascii
    $s18 = "(hZIzq) + (nENt) + (QxZj);};function P(){return 22;};function Zlfgp(){var o = new this[(function KI(){return cYNsr;}())]();var d" ascii
    $s19 = "on Z0(){return yN;}()) + (HToFF) + (function KSrWz(){return UeM;}())]((function Kq(){return GJcyH;}()) + (JFxu)) + (function qn(" ascii
    $s20 = "rn k;}())](bDpDl, 0, 0);};function OvrK(){return (function ax(){return LSH;}()) + (function dqmX(){return L;}()) + (function F0(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}