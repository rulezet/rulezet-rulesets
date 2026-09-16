rule sig_20160318_2806b969372c7191c0c2442f9db2c7f3 {
  meta:
    description = "datamaliciousorder - file 20160318_2806b969372c7191c0c2442f9db2c7f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29cd11cefbd8871b6e1df8933289e162ede6c2ba64ac205c47f633825bf10b29"

  strings:
    $s1  = "var GxhYB = \"ain\\x21\";var UeNut = \"ag\";var WGm = \"ry \";var XcfUr = \", t\";var RJZyB = \"eiu\"[\"charAt\"](0);var MCBBa =" ascii
    $s2  = "r pgS = \"Qb0v6hB\"[\"charAt\"](1);var gtHtt = \"teO\";var Ocoaf = \"Cr\\x65\\x61\";var iuwH = function ZAJdL() {return WScript[" ascii
    $s3  = "PnmF;}()) + (function FvD(){return HeQ;}()) + (function tPt(){return uCCnk;}()); hSruz = dnNJ(); jgZAN = WScript[(function vXVb(" ascii
    $s4  = "n xUJtZ;}()) : (function KwG(){return wqU;}()) + (sX) + (YuLM);}else{WScript.Echo((function fs(){return MCBBa;}()) + (function L" ascii
    $s5  = ")]();var PnAnW = Tkt[(WWz) + (function IvWVz(){return Ut;}()) + (OBrTp) + (nevHo) + (function rGiJ(){return gjhL;}())]();WScript" ascii
    $s6  = "ion tO(){return qE;}()) + (function QeY(){return Nmf;}()) + (function LpdRz(){return W;}())] < 4 ) {WScript[(L) + (function tuK(" ascii
    $s7  = "(){return OBrTp;}()) + (nevHo) + (function AC(){return gjhL;}())]();WScript[(L) + (mc)](nAhzH());var Tkt = new this[(J) + (eaKrK" ascii
    $s8  = "){return mc;}())](nAhzH() * 10)};OOYZw = WScript[S()]((function OpNc(){return D0;}()) + (function Q(){return TUU;}()) + (fgQlt) " ascii
    $s9  = " true;break;}}function CGnh() {return IMkD && AUW;};if (CGnh()){Glgi = iuwH[(NgjMZ) + (function L0(){return cCNq;}()) + (functio" ascii
    $s10 = " I(){return nevHo;}()) + (gjhL)]();var fXQS = \"SKCLH\";fXQS = vWv(PnAnW, KaWlK);var bRbi = \"tS\";bRbi = vWv(VKO, PnAnW);return" ascii
    $s11 = "SzF(){return Ocoaf;}()) + (function QMv(){return gtHtt;}()) + (function Ypfg(){return pgS;}()) + (function ijh(){return iEpw;}()" ascii
    $s12 = "ya(){return W0;}()) + (function d0(){return axP;}())]();stblD(Glgi);fXQS = \"\" + (function lAZ(){return xzA;}()) + (pc) + (func" ascii
    $s13 = "nUChc(){return eN;}()) + (function y(){return sm;}()) + (function wy(){return CTa;}());};function vWv(CALa, DShW){return CALa - " ascii
    $s14 = "(function D2(){return lkU;}()) + (function z(){return oN;}()) + (function QQNOD(){return ESu;}())](Glgi, 2 );OOYZw[(function BYm" ascii
    $s15 = "turn ynJ;}()) + (a) + (function Tx(){return PT;}()) + (function uNn(){return lT;}()) + (function DM(){return tlYm;}()) + (VS), f" ascii
    $s16 = ") + (Xlnp)]((function ZSF(){return nYDs;}()) + (function u(){return hoh;}()) + (function KRZ(){return k;}()) + (Acn));}();functi" ascii
    $s17 = "tion R(){return eaKrK;}())]();var VKO = Tkt[(WWz) + (function iR(){return Ut;}()) + (function jG(){return OBrTp;}()) + (function" ascii
    $s18 = " w0;}()) + (function WJ(){return w1;}()) + (function WWhsu(){return VW;}()) + (function ZJrU(){return aNxXr;}()) + (function lrL" ascii
    $s19 = "return QMiGN;}()) + (T1)] = 1;OOYZw[(m) + (veqOE)](jgZAN[(function EydsB(){return Zg;}()) + (function L1(){return D1;}()) + (fun" ascii
    $s20 = "alse);jgZAN[(function DH(){return a0;}()) + (function x0(){return qI;}())]();while (jgZAN[(function GF(){return T0;}()) + (funct" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}