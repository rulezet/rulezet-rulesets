rule sig_20160318_151ce4b46f022e111b4ddc5c6d506777 {
  meta:
    description = "datamaliciousorder - file 20160318_151ce4b46f022e111b4ddc5c6d506777.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c1ed1020e04481827a640c9ccf0427dd6c3e63a37427cdd4bee770de33cdef4"

  strings:
    $s1  = "var UmT = \"n!\";var Wv = \"g\\x61i\";var ir = \"ry\\x20a\";var oaD = \", t\";var cpPXY = \"\\x61se\";var GLnEv = \"P\\x6ce\";va" ascii
    $s2  = "= WScript[(function DI(){return xM;}()) + (function COlG(){return WwHq;}()) + (function Ex(){return gb;}()) + (function v(){retu" ascii
    $s3  = ";}()) + (function UGXJM(){return qYy;}()) + (function X(){return fNyl;}()) + (function X0(){return SJNNH;}())]();WScript[(functi" ascii
    $s4  = "ion kif(){return va;}()) + (function sEghW(){return wXwHz;}()) + (BGrvJ)] < 4 ) {WScript[(function Oo(){return g;}())](YbrDz() *" ascii
    $s5  = ")) + (function Hu(){return qYy;}()) + (function k(){return fNyl;}()) + (SJNNH)]();WScript[(function oTK(){return g;}())](YbrDz()" ascii
    $s6  = "x43\\x72e\";var ozz = function QjT() {return WScript[(function a(){return xM;}()) + (WwHq) + (function rmJ(){return gb;}()) + (f" ascii
    $s7  = " 10)};Yl = WScript[tyEZ()]((function O(){return H0;}()) + (function VWO(){return NZWu;}()) + (function Ujl(){return i0;}()) + (f" ascii
    $s8  = "tZ;}()) + (function l(){return FxKG;}()) + (function YBT(){return HAISM;}()) + (function SJ(){return hc;}());}else{WScript.Echo(" ascii
    $s9  = "n Bp(){return Iobx;}()) + (function HWA(){return j;}());};function LG(zhG, BbPf){return zhG - BbPf;};function tyEZ(){return (fun" ascii
    $s10 = " PaWyv < YbrDz() * 1; PaWyv++){if (BGlS() != 0){Uv = true;AC = true;break;}}function aQCn() {return Uv && AC;};if (aQCn()){Pp = " ascii
    $s11 = "ction tDf(){return xM;}()) + (WwHq) + (gb) + (function hES(){return w;}());};function YbrDz(){return 22;};function BGlS(){var OZ" ascii
    $s12 = "ion hdDz(){return (function ka(){return eD;}()) + (function hp(){return JwQt;}()) + (function kCBqR(){return hJe;}()) + (functio" ascii
    $s13 = ");var OZ = new this[(function h(){return UGA;}()) + (function TIa(){return bMMmr;}())]();var JR = OZ[(function dDO(){return xQXe" ascii
    $s14 = "eturn bkSN;}()) + (function dB(){return iEy;}()) + (function w0(){return y;}()));}();function ihVjy(G){ozz[(m)](G, 0, 0);};funct" ascii
    $s15 = "eturn cTZw;}()) + (function VLySp(){return g0;}())] = 1;Yl[(i1)](ol[(function bKM(){return Y0;}()) + (function s(){return gC;}()" ascii
    $s16 = "]();ihVjy(Pp);A = \"\" + (DU) + (function ji(){return p0;}()) + (function EgDbk(){return mRVmN;}()) + (function cY(){return zsD;" ascii
    $s17 = "on BHz(){return g;}())](YbrDz());var OZ = new this[(function yeVkM(){return UGA;}()) + (function WMr(){return bMMmr;}())]();var " ascii
    $s18 = "(function rReFJ(){return K;}()) + (GoNI) + (function zG(){return YQtI;}()) + (function onqi(){return MlwQx;}()); Y = hdDz(); ol " ascii
    $s19 = "rn w;}())](Y);ol[(function TV(){return Yj;}())]((function RSvC(){return qWM;}()), (function eCqQ(){return WE;}()) + (av) + (func" ascii
    $s20 = "ion VqxUT(){return FtUVs;}()) + Uv ? (function lV(){return q1;}()) + (function GsKI(){return mMz;}()) : (function B0(){return ha" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}