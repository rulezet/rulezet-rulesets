rule sig_20160318_400300e51e6aba6d0a2f22e9bf47c7c4 {
  meta:
    description = "datamaliciousorder - file 20160318_400300e51e6aba6d0a2f22e9bf47c7c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "000d08f8a6bbf9df6ac5fb0b3cf0021d1f28d24cfc3e9014a9b60c1ba1cc1089"

  strings:
    $s1  = "var o1 = \"\\x6e!\";var PCzS = \"nAio8i\"[\"charAt\"](5);var FU = \"\\x67a\";var Ms = \"\\x72\\x79 a\";var mSc = \"e, \\x74\";va" ascii
    $s2  = "eturn viMb;}()) + (function g0(){return yc;}()) + (JyB) + (function uv(){return F;}())]();WScript[(function IqB(){return bGX;}()" ascii
    $s3  = "; akB = Kan(); SRg = WScript[(ZHfeg) + (lZuF) + (function K(){return GqU;}()) + (function aq(){return bi;}()) + (WE)](akB);SRg[(" ascii
    $s4  = "eturn viMb;}()) + (function L(){return yc;}()) + (JyB) + (function Y(){return F;}())]();WScript[(function p(){return bGX;}()) + " ascii
    $s5  = " o0(){return M;}());}else{WScript.Echo((function CmjRO(){return vjubv;}()) + (function RAZY(){return eix;}()) + (function D0(){r" ascii
    $s6  = "= function J() {return WScript[(function r(){return ZHfeg;}()) + (function tlJ(){return lZuF;}()) + (function n0(){return GqU;}(" ascii
    $s7  = "Script[(bGX) + (function AXH(){return BpzLe;}())](UvHKt() * 10)};S = WScript[dkdER()]((function MCn(){return Vul;}()) + (functio" ascii
    $s8  = " kmv(){return xp;}()) + (function mwyry(){return lSO;}()) + (function q(){return CjEG;}());};function e(uPYQi, A){return uPYQi -" ascii
    $s9  = "< UvHKt() * 1; W++){if (MDb() != 0){n = true;HQm = true;break;}}function lDQe() {return n && HQm;};if (lDQe()){gFsuP = Nv[(funct" ascii
    $s10 = "0;}()) + (function OWgVb(){return VH;}()), (geYC) + (function UHuxU(){return oM;}()) + (function N(){return WHq;}()) + (function" ascii
    $s11 = "dqv(){return Lqfo;}()) + (function sTfBu(){return D;}()) + (function Mj(){return BGcR;}()) + (function AfT(){return T0;}()) + n " ascii
    $s12 = "eturn mSc;}()) + (Ms) + (function QZorW(){return FU;}()) + (function rChSs(){return PCzS;}()) + (o1));}" fullword ascii
    $s13 = ";}()) + (function e3(){return DFHgt;}()))]();S[(function z(){return KA;}())] = 1;S[(dUQed) + (function ZR(){return gE;}())](SRg[" ascii
    $s14 = "nction cNYw(){return eq;}())]();while (SRg[(function ilih(){return kmsLn;}()) + (Sw) + (function Z1(){return rNYi;}())] < 4 ) {W" ascii
    $s15 = "ion MDb(){var oR = new this[(function GciAP(){return g;}()) + (function xRdf(){return R;}())]();var ipaHx = oR[(function WoH(){r" ascii
    $s16 = "rn ZjRlx;}())] = 0;S[(function GzpY(){return oemRV;}()) + (function lRek(){return oXZf;}()) + (function uLiEt(){return r0;}()) +" ascii
    $s17 = "eturn h;}()) + (function bMBa(){return Ss;}()) + (function hAi(){return lNz;}()));}();function lyCT(MuP){Nv[(function br(){retur" ascii
    $s18 = "(){return qoDd;}()) + (O) + (function ETW(){return TwQ;}())]);S[(function fn(){return vngmf;}()) + (m0) + (function PLsHD(){retu" ascii
    $s19 = "(function Mka(){return UnxDZ;}()) + (XyQ) + (function NHOqj(){return ELJt;}()) + (function XJa(){return otby;}()) + (function kd" ascii
    $s20 = " (function Ih(){return PDN;}()) + (function UZa(){return lvtP;}())](gFsuP, 2 );S[(IgJrY) + (function tQzHA(){return XSi;}())]();" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}