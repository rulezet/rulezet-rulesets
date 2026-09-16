rule sig_20160318_287d840dca6435612f2365bf8e731f91 {
  meta:
    description = "datamaliciousorder - file 20160318_287d840dca6435612f2365bf8e731f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee0d29040c45ca1aec98bd6b91c754cfa52bb5509a00476f9a62afc8f3b42e46"

  strings:
    $s1  = "var lCM = \"g\\x61\\x69\\x6e\\x21\";var ZBNZ = \"\\x74ry\\x20a\";var H = \", \";var M = \"l\\x65a\\x73e\";var BjGHc = \"P\";var " ascii
    $s2  = "on SlP(){return q;}()) + (function a(){return nz;}()) + (function p(){return wqU;}()) + (function m(){return ooz;}())]();WScript" ascii
    $s3  = " 4 ) {WScript[(fbX) + (e)](sgbm() * 10)};husts = WScript[zoHs()]((function JUZ(){return ylj;}()) + (function Ss(){return Rw;}())" ascii
    $s4  = "(){return nz;}()) + (function Z(){return wqU;}()) + (function smmt(){return ooz;}())]();WScript[(function bhvaE(){return fbX;}()" ascii
    $s5  = "()) + (ZzxzK) + (function cX(){return NNCl;}()) + (GAB); y = bLw(); WnxhG = WScript[(function h(){return laO;}()) + (APiwx) + (f" ascii
    $s6  = "(function k(){return mAQ;}()) + (ZUHf) + (function CdfUM(){return zf0;}());}else{WScript.Echo((function htH(){return BjGHc;}()) " ascii
    $s7  = "wtT, YEj){return NwtT - YEj;};function zoHs(){return (laO) + (function NDPxB(){return APiwx;}()) + (pS) + (HamWF) + (ZzE);};func" ascii
    $s8  = "l() {return v && wi;};if (rwwAl()){nohS = G[(Dve) + (function Blh(){return PlH;}()) + (function ja(){return BL;}()) + (JpU) + (W" ascii
    $s9  = "jObD(){return ZQQj;}()) + (function CiBz(){return wU;}()));}();function asoha(gX){G[(function BksM(){return latGg;}()) + (functi" ascii
    $s10 = ") + (function y0(){return e;}())](sgbm());var Di = new this[(function XP(){return xfEb;}())]();var swTi = Di[(function NyqlI(){r" ascii
    $s11 = "nction oHIo(){return zcj;}()) + (function pT(){return zEy;}()) + (HF)](nohS, 2 );husts[(hDFJU) + (function wGZ(){return c;}())](" ascii
    $s12 = ") + (VI) + (function qyC(){return t;}()) + (function AQ(){return x;}()) + (HQe)]((function FCY(){return I;}()) + (fxgYB) + (func" ascii
    $s13 = " pgx(){return GfXH;}()) + (function L(){return Jm;}()) + (function PUro(){return MQzm;}()) + (XDU) + (SBV) + (zuEE), false);Wnxh" ascii
    $s14 = "turn t2;}()) + (function mj(){return cUO;}()) + v ? (function YFx(){return Q;}()) + (QTI) + (function WXC(){return OlNhw;}()) : " ascii
    $s15 = "{return OmB;}()) + (function exxj(){return V;}()), (function AH(){return KKLY;}()) + (function xsT(){return jus;}()) + (function" ascii
    $s16 = "+ (function O1(){return M;}()) + (H) + (function iKoRO(){return ZBNZ;}()) + (function Q0(){return lCM;}()));}" fullword ascii
    $s17 = ";var jPBIY = Di[(function Fbn(){return HpZN;}()) + (function GRJt(){return ch;}()) + (function g(){return q;}()) + (function LTv" ascii
    $s18 = "on n(){return eO;}())](gX, 0, 0);};function bLw(){return (ps) + (kBSk) + (GM) + (function h0(){return zF;}());};function CvGWH(N" ascii
    $s19 = "[(function MkGB(){return fbX;}()) + (function zuV(){return e;}())](sgbm());var Di = new this[(function bEf(){return xfEb;}())]()" ascii
    $s20 = "G[(function DIaN(){return L0;}())]();while (WnxhG[(Au) + (function awts(){return mHsk;}()) + (function Jb(){return mlaIW;}())] <" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}