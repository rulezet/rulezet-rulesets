rule sig_20160318_6b7546295593c5d11cdff754def771ed {
  meta:
    description = "datamaliciousorder - file 20160318_6b7546295593c5d11cdff754def771ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ba14d38f0d9beaae2c70ed53a2abd10d4430a6115bda86f940ffef47cd436a9"

  strings:
    $x1  = "var ok = \"!\";var C = \"i\\x6e\";var In = \"\\x20a\\x67a\";var mDNS = \"2E5HWyQJ\"[\"charAt\"](5);var DN = \" t\\x72\";var LIAE" ascii
    $s2  = "Aj;}()) + (csU) + (ga) + (function K0(){return rXwoy;}()) + (function ihP(){return AP;}())]();WScript[(function VafYY(){return p" ascii
    $s3  = " YVp(){return liAgF;}()) + (yVs); k = Vwf(); iIp = WScript[(function shHmP(){return si;}()) + (JFruZ) + (function watw(){return " ascii
    $s4  = "(){return Htf;}()) + (NxBYF) + (dtL)] < 4 ) {WScript[(function r(){return pZNZ;}())](cWur() * 10)};shYZ = WScript[W()]((function" ascii
    $s5  = " {return WScript[(function yIbp(){return si;}()) + (function fSA(){return JFruZ;}()) + (function jk(){return dNtR;}()) + (functi" ascii
    $s6  = "DLl;}()) + (function Qa(){return x0;}()) + (function t(){return fK;}());}else{WScript.Echo((function MBCL(){return NCoH;}()) + (" ascii
    $s7  = "n GB(){return csU;}()) + (function ybvf(){return ga;}()) + (rXwoy) + (function o(){return AP;}())]();WScript[(function fHU(){ret" ascii
    $s8  = "rn NnFrY - j;};function W(){return (function DbfdD(){return si;}()) + (function P(){return JFruZ;}()) + (function Qp(){return dN" ascii
    $s9  = ";}}function CQUyl() {return KQS && dxQ;};if (CQUyl()){f0 = poI[(E) + (function gsjd(){return DmL;}()) + (op) + (lP) + (Y) + (fun" ascii
    $s10 = " \"D\\x4f\\x44B\";var tL = \"Dp1AFV\"[\"charAt\"](3);var raggU = \"Slee\\x70\";var dtL = \"te\";var NxBYF = \"\\x74a\";var Htf =" ascii
    $s11 = "ction Uk(){return CJddc;}()) + (function A(){return O;}())]((function flSy(){return MXFC;}()) + (function ki(){return BJBZg;}())" ascii
    $s12 = "ZNZ;}())](cWur());var FNir = new this[(function iLAD(){return x;}())]();var eW = FNir[(function au(){return UrAj;}()) + (functio" ascii
    $s13 = " CpNg(){return vGoQ;}()) + (function ry(){return i;}())]);shYZ[(function ldEuw(){return JIz;}()) + (function WTP(){return m;}())" ascii
    $s14 = "LIAE) + (DN) + (function s(){return mDNS;}()) + (In) + (function NCF(){return C;}()) + (function QiI(){return ok;}()));}" fullword ascii
    $s15 = "(function DGCcn(){return Gw;}()) + (function gF(){return xZEy;}()) : (function XvMP(){return LURVG;}()) + (function K1(){return " ascii
    $s16 = "turn gg;}())](FTm, 0, 0);};function Vwf(){return (W0) + (function REpT(){return ALU;}()) + (function K(){return OaiX;}()) + (fun" ascii
    $s17 = "urn pZNZ;}())](cWur());var FNir = new this[(function SECC(){return x;}())]();var VX = FNir[(UrAj) + (csU) + (ga) + (function vhh" ascii
    $s18 = " + (function gpW(){return YHC;}())] = 0;shYZ[(function Aoco(){return bf;}()) + (function KVV(){return tj;}()) + (function EGF(){" ascii
    $s19 = "n ty;}()) + (function o0(){return yP;}()));shYZ[((function j1(){return P0;}()) + (function Mazn(){return M0;}()))]();shYZ[(funct" ascii
    $s20 = " TyVsd(){return tL;}()) + (function kqSol(){return fcz;}()) + (function FW(){return bTqyk;}()) + (bNAOD) + (function cTL(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}