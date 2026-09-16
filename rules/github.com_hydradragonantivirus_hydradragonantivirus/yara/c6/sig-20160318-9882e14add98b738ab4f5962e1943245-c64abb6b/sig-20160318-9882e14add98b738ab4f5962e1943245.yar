rule sig_20160318_9882e14add98b738ab4f5962e1943245 {
  meta:
    description = "datamaliciousorder - file 20160318_9882e14add98b738ab4f5962e1943245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f973ed019fed7c1eb6fd2cce588fb369a0afa183044da002e27c88646fc6311"

  strings:
    $s1  = "var S0 = \"\\x69n!\";var zwaH = \" ag\\x61\";var N0 = \" t\\x72y\";var ZXuLJ = \"ase,\";var jF = \"\\x50le\";var iECiF = \"2\";v" ascii
    $s2  = "\\x6a\";var mZAw = \"3DQeBkTjG\"[\"charAt\"](3);var f = \"eat\";var IjoEV = \"Cr\";var VcW = function pFA() {return WScript[(fun" ascii
    $s3  = " < 4 ) {WScript[(function X(){return GTg;}())](PXk() * 10)};Um = WScript[XQ()]((jg) + (function n0(){return VnAEL;}()) + (functi" ascii
    $s4  = " + (function f0(){return HLCDQ;}()) + (function tdYoO(){return S;}()) + (i)]();WScript[(GTg)](PXk());var xF = new this[(TiuQ)]()" ascii
    $s5  = ";var FKhx = xF[(xLtO) + (HLCDQ) + (function Ytu(){return S;}()) + (function gh(){return i;}())]();WScript[(function TIuIW(){retu" ascii
    $s6  = "MYFPu;}()) : (function RtFZ(){return sZ;}()) + (function cM(){return yIhnx;}()) + (iECiF);}else{WScript.Echo((function Qqf(){ret" ascii
    $s7  = "return WhWs;}()); q = xNFJ(); CDjzN = WScript[(function CcixI(){return IjoEV;}()) + (function Ur(){return f;}()) + (function TE(" ascii
    $s8  = "G;}());};function jLj(vw, sK){return vw - sK;};function XQ(){return (function mk(){return IjoEV;}()) + (f) + (function xdb(){ret" ascii
    $s9  = "() {return KvoU && zwZu;};if (uZQn()){O = VcW[(function E(){return oF;}()) + (RVn) + (function lT(){return XXKo;}()) + (function" ascii
    $s10 = ")) + (function IB(){return edVpe;}()) + (function OPCn(){return GkZ;}()), false);CDjzN[(bZ) + (hjKEv)]();while (CDjzN[(function " ascii
    $s11 = "function WVkh(){return rxRdP;}()) + (function z(){return yYn;}()) + (function N(){return jvQ;}()) + (lp) + (function KJh(){retur" ascii
    $s12 = "n i0;}()) + (function Wlx(){return UmXV;}()) + (function jMeM(){return EQ;}()) + (awQO) + (function ZGM(){return lI;}()) + (func" ascii
    $s13 = "hOe(){return hrtQw;}()) + (function HG(){return Ij;}()) + (function ybmo(){return tOpXw;}()) + (function M0(){return ZPQwP;}())]" ascii
    $s14 = "rn tJ;}()) + (function jRGI(){return HD;}())](O, 2 );Um[(doIO) + (function Hh(){return dWM;}())]();s(O);QbMcD = \"\" + (abMWi) +" ascii
    $s15 = "urn mZAw;}()) + (function VjnR(){return G;}()) + (function aea(){return Z;}()) + (function oM(){return CGVLw;}());};function PXk" ascii
    $s16 = "DjzN[(function oHoTK(){return PRJy;}())]((function BI(){return P;}()) + (qx), (bPi) + (function NO(){return rIbxV;}()) + (functi" ascii
    $s17 = "rn GTg;}())](PXk());var xF = new this[(function NBRz(){return TiuQ;}())]();var xCByH = xF[(xLtO) + (HLCDQ) + (S) + (function DZ(" ascii
    $s18 = "){return lhAt;}())]((LavxB) + (function Cy(){return U0;}())) + (function Mpedv(){return xLoW;}()) + (function jC(){return l;}())" ascii
    $s19 = "){return mZAw;}()) + (function apnB(){return G;}()) + (function TDQO(){return Z;}()) + (function QDeBd(){return CGVLw;}())](q);C" ascii
    $s20 = " d(){return Hrvp;}()) + (mZDn)] = 0;Um[(function XTEg(){return PkVJM;}()) + (function F0(){return pt;}()) + (function MBN(){retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}