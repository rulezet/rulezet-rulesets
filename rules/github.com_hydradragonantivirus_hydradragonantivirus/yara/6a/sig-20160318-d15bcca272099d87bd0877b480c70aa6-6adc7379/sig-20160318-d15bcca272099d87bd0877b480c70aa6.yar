rule sig_20160318_d15bcca272099d87bd0877b480c70aa6 {
  meta:
    description = "datamaliciousorder - file 20160318_d15bcca272099d87bd0877b480c70aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f485975ba34f964a958bb2b39e39103d9ff7154515f9f88a54a82cc81c77d053"

  strings:
    $s1  = "var JZst = \"\\x21\";var yxJ = \"ag\\x61i\\x6e\";var tURNI = \"y\\x20\";var d1 = \"wy9rP5G0H\"[\"charAt\"](3);var DZG = \"t\";va" ascii
    $s2  = "Script.Echo((function S0(){return rH;}()) + (function m0(){return k0;}()) + (function S1(){return DZG;}()) + (d1) + (tURNI) + (f" ascii
    $s3  = "4MR\"[\"charAt\"](0);var MkmR = \"jec\";var bfzM = \"t\\x65Ob\";var xoiV = \"\\x43\\x72ea\";var s = function Rn() {return WScrip" ascii
    $s4  = "{return KY;}()) + (function zpesn(){return OnXUe;}()) + (yEn)]();WScript[(function HYh(){return sJuIp;}()) + (function poC(){ret" ascii
    $s5  = " + (OnXUe) + (function fW(){return yEn;}())]();WScript[(function kRe(){return sJuIp;}()) + (function LNvGu(){return jb;}())](t()" ascii
    $s6  = "rn GT;}()) + (WPe) + (function x1(){return c1;}())] < 4 ) {WScript[(function YE(){return sJuIp;}()) + (function LtWCy(){return j" ascii
    $s7  = "b;}())](t() * 10)};AwJ = WScript[EFUuN()]((function JBwYO(){return dbM;}()) + (xm) + (function dZ(){return WDu;}()) + (function " ascii
    $s8  = "Vg) + (function jAV(){return d0;}()) + (function L(){return UYxMU;}());};function iV(IIOwB, e){return IIOwB - e;};function EFUuN" ascii
    $s9  = "false;for (var ejfc = 0; ejfc < t() * 1; ejfc++){if (JcRaS() != 0){j = true;ygv = true;break;}}function Bjme() {return j && ygv;" ascii
    $s10 = ") + (function VWv(){return quHlQ;}())](OW, 2 );AwJ[(function LTiDS(){return gr;}()) + (function Hw(){return qwYzO;}())]();T(OW);" ascii
    $s11 = " + (function bmnV(){return Cdfzh;}()) + (function c(){return LJAD;}()) + (function neQR(){return p;}()) + (HPF));}();function T(" ascii
    $s12 = "unction ezFXl(){return yxJ;}()) + (JZst));}" fullword ascii
    $s13 = "w) + j ? (function ksBf(){return IePg;}()) + (function Oc(){return ojVu;}()) + (function Rt(){return bU;}()) + (function AnGN(){" ascii
    $s14 = "v0(){return dR;}()));AwJ[((function kNld(){return lscRN;}()) + (function eAyiq(){return BpiNx;}()))]();AwJ[(function IURUw(){ret" ascii
    $s15 = "AXFk) + (rVe), false);oG[(function yprJq(){return lbMBh;}())]();while (oG[(function Izw(){return dTBk;}()) + (function ia(){retu" ascii
    $s16 = "nZ;}()) + (function kz(){return KlVr;}()) + (function ehd(){return EuL;}())]);AwJ[(function Z0(){return ENUO;}()) + (function Ul" ascii
    $s17 = " + (BpiNx)]((cX), (function ymX(){return GpI;}()) + (function Q(){return x0;}()) + (frZo) + (function YgIl(){return e0;}()) + (f" ascii
    $s18 = "urn pnH;}()) + (function JIR(){return yOnyX;}())] = 1;AwJ[(dvP) + (function txSMo(){return GAJ;}())](oG[(function deg(){return G" ascii
    $s19 = "){return xZvMf;}()) + (function SaqT(){return so;}()) + (function rVuG(){return sWTby;}()) + (function B(){return wFiio;}()) + (" ascii
    $s20 = "function lMzDK(){return xDwDH;}()) + (qVABW) + (function JY(){return Lnz;}()) + (function H(){return SEr;}()) + (function lX(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}