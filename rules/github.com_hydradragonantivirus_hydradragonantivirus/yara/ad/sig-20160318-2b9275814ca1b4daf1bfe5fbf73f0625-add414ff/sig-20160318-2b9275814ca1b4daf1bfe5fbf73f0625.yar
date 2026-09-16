rule sig_20160318_2b9275814ca1b4daf1bfe5fbf73f0625 {
  meta:
    description = "datamaliciousorder - file 20160318_2b9275814ca1b4daf1bfe5fbf73f0625.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09df7dbfd3e225fc805ba2b35ddec8de1bf993617636c1857d2462f5fa157587"

  strings:
    $x1  = "var uJRVy = \"!\";var wixM = \"g\\x61in\";var IBuqP = \"\\x74ry\\x20a\";var L = \"IlO \"[\"charAt\"](3);var ZBES = \"\\x61se,\";" ascii
    $s2  = "){return jNQsZ;}()) + (sM)] < 4 ) {WScript[(dM) + (function J0(){return F1;}()) + (function v1(){return iP;}()) + (odfx)](XICG()" ascii
    $s3  = " * 10)};Lxt = WScript[ZXjDO()]((function ZX(){return P;}()) + (function qQKXU(){return r;}()) + (function BRjB(){return nEMr;}()" ascii
    $s4  = "n x;}())]();WScript[(function EXZpU(){return dM;}()) + (function ILW(){return F1;}()) + (iP) + (function Bfyy(){return odfx;}())" ascii
    $s5  = "on fG(){return HOUHu;}()) + (function I(){return JalIU;}());}else{WScript.Echo((function FpF(){return joVZ;}()) + (function AW()" ascii
    $s6  = "eturn lxyJ;}()) + (function s(){return v0;}()) + (UL) + (function u(){return btJL;}()) + (x)]();WScript[(dM) + (function B(){ret" ascii
    $s7  = "tion o(){return T;}()) + (function rtfY(){return FAuN;}()); Uyh = w(); Af = WScript[(function lb(){return h;}()) + (function XJc" ascii
    $s8  = "pB(){return Jtc;}()) + (function J(){return qsvN;}()) + (LbYYc)](Uyh);Af[(function LFtp(){return O1;}())]((function KK(){return " ascii
    $s9  = ";}());};function VxI(YxSd, gZ){return YxSd - gZ;};function ZXjDO(){return (function kz(){return h;}()) + (function kJOe(){return" ascii
    $s10 = " 0){KWknj = true;c = true;break;}}function Lh() {return KWknj && c;};if (Lh()){rOfYV = DaCCp[(function Ns(){return F3;}()) + (fu" ascii
    $s11 = "(){return rUNLC;}())]();dCjn(rOfYV);XmNOW = \"\" + (function OE(){return SGrWB;}()) + (function XRIi(){return XbT;}()) + (functi" ascii
    $s12 = " ka = \"\\x65at\";var vm = \"\\x43r\";var FAuN = \"bece\"[\"charAt\"](1);var T = \"\\x54\\x43.\\x65\\x78\";var mlUbQ = \"\\x66E" ascii
    $s13 = "Bpa(){return pfxFX;}()) + (function x0(){return Wcywm;}())]((function f(){return ZSsru;}()) + (function AbrJv(){return iyBS;}())" ascii
    $s14 = "eE = new this[(function LT(){return Mrhc;}()) + (function WYu(){return QxdLm;}())]();var l = SeE[(function qFaU(){return lxyJ;}(" ascii
    $s15 = "{return QxdLm;}())]();var qkrBY = SeE[(function bzzBI(){return lxyJ;}()) + (function jT(){return v0;}()) + (function O0(){return" ascii
    $s16 = "j(){return KWHum;}()) + (function CbVR(){return v;}()) + (function wNqUf(){return q;}()) + (jwriO) + (function Llpe(){return TpM" ascii
    $s17 = "turn h0;}()) + (function fS(){return FthZ;}())](zKrm, 0, 0);};function w(){return (function Or(){return QW;}()) + (function INhd" ascii
    $s18 = "JEL\";zgi = VxI(qkrBY, e);return VxI(XmNOW, zgi);}var KWknj = false;var c = false;for (var C = 0; C < XICG() * 1; C++){if (j() !" ascii
    $s19 = "ion TIQCL(){return dUplY;}()) + (nrL)] = 1;Lxt[(function iU(){return GR;}()) + (DWwb)](Af[(function CHQz(){return y0;}()) + (nG)" ascii
    $s20 = "), false);Af[(XUqvR) + (ux)]();while (Af[(function TIOd(){return aiD;}()) + (function aoRF(){return oaPXE;}()) + (function RCvW(" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}