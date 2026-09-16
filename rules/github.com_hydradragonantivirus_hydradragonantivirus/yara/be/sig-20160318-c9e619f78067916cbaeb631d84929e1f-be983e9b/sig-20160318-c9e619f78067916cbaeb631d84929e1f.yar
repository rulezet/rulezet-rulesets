rule sig_20160318_c9e619f78067916cbaeb631d84929e1f {
  meta:
    description = "datamaliciousorder - file 20160318_c9e619f78067916cbaeb631d84929e1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54bba2d855ae310534cbc5108904d4cbac43165ba9cdbda12fdb10d8fdc844e8"

  strings:
    $s1  = "var GFH = \"n!\";var Aub = \"a\\x69\";var KSgUF = \"\\x61\\x67\";var fzc = \"\\x74ry \";var ItLl = \" \";var gsOQz = \"1we,G\"[" ascii
    $s2  = " (function rz(){return WSZa;}()) + (function ZuXb(){return uI;}()) + (function iVY(){return vbbpX;}())]();WScript[(function VeKu" ascii
    $s3  = "WScript[(function pgg(){return s;}()) + (function JDE(){return dL;}()) + (function k0(){return an;}())](a() * 10)};fLGIn = WScri" ascii
    $s4  = ")) + (uI) + (function ZyzGo(){return vbbpX;}())]();WScript[(function yBSqt(){return s;}()) + (dL) + (function QwH(){return an;}(" ascii
    $s5  = "}()) + (FT) + (function DPnaA(){return MODjf;}()) + (function ASWz(){return IYrmQ;}()); mtaPf = bl(); CI = WScript[(function CKU" ascii
    $s6  = "eturn ohcRv;}()) + (wnMG) + (UZmGl);}else{WScript.Echo((function Yra(){return H0;}()) + (function Q(){return U0;}()) + (function" ascii
    $s7  = "\"eateO\";var iYyEP = \"Cr\";var t = function OuLZ() {return WScript[(function O(){return iYyEP;}()) + (function h(){return p;}(" ascii
    $s8  = "on HSSvf(CVm, BGuCg){return CVm - BGuCg;};function iy(){return (function RHFE(){return iYyEP;}()) + (function mHarV(){return p;}" ascii
    $s9  = "ue;break;}}function xkufV() {return JOg && B;};if (xkufV()){t0 = t[(rBUYa) + (pnvPr) + (function QEVLT(){return jS;}()) + (yV) +" ascii
    $s10 = "{return BrWp;}()) + (function I(){return wRS;}()) + (function DrgfM(){return yS;}()) + (function HEmq(){return bwma;}()) + (func" ascii
    $s11 = "Aub;}()) + (function xT(){return GFH;}()));}" fullword ascii
    $s12 = "u(){return s;}()) + (function pePG(){return dL;}()) + (function qTNf(){return an;}())](a());var Vv = new this[(function H(){retu" ascii
    $s13 = " jpMG(){return gsOQz;}()) + (function HBz(){return ItLl;}()) + (fzc) + (function Kgo(){return KSgUF;}()) + (function b(){return " ascii
    $s14 = "function nOTf(){return Nmn;}()) + (function GbmiZ(){return Ye;}()) + (function ijSfA(){return WlEPm;}()), false);CI[(BX) + (func" ascii
    $s15 = ";}())](k, 0, 0);};function bl(){return (function Zpg(){return ncJ;}()) + (xF) + (e) + (function Jds(){return GrSpo;}());};functi" ascii
    $s16 = "))]();var Z = Vv[(SazUo) + (function Sx(){return RbsPm;}()) + (function Dhk(){return RXPyX;}()) + (function KoX(){return WSZa;}(" ascii
    $s17 = "()) + (function Hb(){return IyD;}());};function a(){return 22;};function tuzSX(){var Vv = new this[(function zC(){return anzs;}(" ascii
    $s18 = "rn anzs;}())]();var Fchvv = Vv[(function M(){return SazUo;}()) + (RbsPm) + (function w(){return RXPyX;}()) + (WSZa) + (function " ascii
    $s19 = "n GUFs;}()) + (tX) + (function PfXI(){return SISnO;}()) + (function LzIB(){return bVCI;}()) + (function mjAA(){return L;}()) + (" ascii
    $s20 = "tion gIsn(){return ygbE;}()) + (function Vqs(){return bp;}()) + (function YAm(){return wPrJy;}()) + (function pfdtc(){return Dd;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}