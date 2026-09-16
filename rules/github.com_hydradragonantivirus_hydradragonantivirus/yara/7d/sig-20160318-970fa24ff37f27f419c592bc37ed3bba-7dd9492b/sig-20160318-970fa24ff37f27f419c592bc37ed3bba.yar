rule sig_20160318_970fa24ff37f27f419c592bc37ed3bba {
  meta:
    description = "datamaliciousorder - file 20160318_970fa24ff37f27f419c592bc37ed3bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02bdd239ae6622111ac1998ee1ddd6d6bdaf55b7e7b685f45080ba276dd8e852"

  strings:
    $s1  = "var R = \"in!\";var bEQAY = \"50kaCl4\"[\"charAt\"](3);var SJown = \"\\x72y ag\";var h0 = \"se,\\x20t\";var EFn = \"Plea\";var b" ascii
    $s2  = "x65\";var WHxps = \"rea\\x74\\x65\";var RlOCD = \"\\x43\";var P = function SK() {return WScript[(function MGKVA(){return RlOCD;}" ascii
    $s3  = "(function Im(){return C0;}()) + (function M(){return c0;}()) + (cH); cnVaU = SxW(); pmD = WScript[(RlOCD) + (WHxps) + (pPXK) + (" ascii
    $s4  = "BFGYR;}()) + (function qB(){return NlGtj;}()) + (AiM) + (function buYWF(){return AoiXi;}()) + (OSiX)]();WScript[(function dqlNO(" ascii
    $s5  = "tion EcRT(){return wpfaT;}())] < 4 ) {WScript[(function OePGh(){return GMh;}())](dHza() * 10)};FkQO = WScript[xZpd()]((function " ascii
    $s6  = "rn r2;}()) + (function bd(){return ALI;}()) + (function UphL(){return b;}());}else{WScript.Echo((EFn) + (function jwWGp(){return" ascii
    $s7  = "PB(){return OSiX;}())]();WScript[(function r0(){return GMh;}())](dHza());var bygk = new this[(function sl(){return Nb;}()) + (fu" ascii
    $s8  = " + (function o(){return iR;}());};function Vr(zIDWk, dAk){return zIDWk - dAk;};function xZpd(){return (function ZTkO(){return Rl" ascii
    $s9  = "= true;GcDK = true;break;}}function vklph() {return nrcS && GcDK;};if (vklph()){Fh = P[(function AXc(){return WH;}()) + (functio" ascii
    $s10 = "OCD;}()) + (function Y(){return WHxps;}()) + (function LOj(){return pPXK;}()) + (plra);};function dHza(){return 22;};function wh" ascii
    $s11 = "0(){return Z;}()) + (function MIf(){return OgCU;}()) + (function BqXB(){return os;}()) + (GQgmA)]);FkQO[(function EEqJm(){return" ascii
    $s12 = "plra)](cnVaU);pmD[(function L(){return MA;}()) + (GyE)]((function eA(){return X;}()), (function cbc(){return WGE;}()) + (functio" ascii
    $s13 = " h0;}()) + (function oLb(){return SJown;}()) + (function Rl(){return bEQAY;}()) + (function Bdwas(){return R;}()));}" fullword ascii
    $s14 = "nction LOf(){return h;}())]();var xg = bygk[(BFGYR) + (function TM(){return NlGtj;}()) + (function Ox(){return AiM;}()) + (funct" ascii
    $s15 = "on VmsWG(){return acGM;}()));FkQO[((MA) + (GyE))]();FkQO[(function mIg(){return Ag;}()) + (E0)] = 1;FkQO[(rebc)](pmD[(function y" ascii
    $s16 = "ion UxaHm(){return AoiXi;}()) + (function XIndT(){return OSiX;}())]();var hc = \"CI\";hc = Vr(TZlks, U);var Ok = \"r\";Ok = Vr(x" ascii
    $s17 = "){return Q0;}()) + (gqoHW) + (function miFtU(){return BDy;}()) : (gW) + (function ZoO(){return DAa;}()) + (function xzTga(){retu" ascii
    $s18 = "unction izER(){return WHxps;}()) + (pPXK) + (function pYXs(){return plra;}())]((function C(){return hXqL;}()) + (function Ov(){r" ascii
    $s19 = "){return GMh;}())](dHza());var bygk = new this[(function puGqh(){return Nb;}()) + (h)]();var TZlks = bygk[(function HN(){return " ascii
    $s20 = "(){return ZRcVt;}()) + (Ku) + (function HZ(){return zH;}()) + (E1) + nrcS ? (function wBxPL(){return AoKY;}()) + (function ADce(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}