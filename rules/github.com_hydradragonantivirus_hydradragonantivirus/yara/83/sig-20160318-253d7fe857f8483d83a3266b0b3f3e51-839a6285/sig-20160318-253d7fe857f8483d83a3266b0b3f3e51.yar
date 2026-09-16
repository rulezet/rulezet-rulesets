rule sig_20160318_253d7fe857f8483d83a3266b0b3f3e51 {
  meta:
    description = "datamaliciousorder - file 20160318_253d7fe857f8483d83a3266b0b3f3e51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d721dca7c99800af1b265941bbeea7ffaaaa96e0e2be976af8ee0cd8eba11a20"

  strings:
    $s1  = "var u = \"ain!\";var LCzNZ = \"ry\\x20\\x61\\x67\";var y1 = \" t\";var N2 = \"e\\x2c\";var fpe = \"l\\x65as\";var nP = \"Pzv\"[" ascii
    $s2  = "ejZy3v\"[\"charAt\"](4);var fHRip = \"Cr\\x65\\x61\\x74\";var CAL = function BWG() {return WScript[(fHRip) + (function LEukt(){r" ascii
    $s3  = "}())] < 4 ) {WScript[(aGy)](j() * 10)};RXh = WScript[YVY()]((function ChSPI(){return BbtAF;}()) + (function G0(){return oY;}()) " ascii
    $s4  = "Ym;}()) + (sBHLK) + (fsw) + (PA) + (uf)]();WScript[(function CZUSU(){return aGy;}())](j());var Tyr = new this[(function FbptB(){" ascii
    $s5  = "ion WJ(){return ZJG;}()); OXXt = o(); gOk = WScript[(function T(){return fHRip;}()) + (function doQk(){return cm;}()) + (TBP) + " ascii
    $s6  = ") + (function lQV(){return fxMJC;}()) + (function Z(){return TpU;}());}else{WScript.Echo((function cJD(){return nP;}()) + (funct" ascii
    $s7  = "();WScript[(function po(){return aGy;}())](j());var Tyr = new this[(Fxs)]();var FxCb = Tyr[(wSbxX) + (function SjJi(){return GiL" ascii
    $s8  = "n dh(yk, WDg){return yk - WDg;};function YVY(){return (function lct(){return fHRip;}()) + (function SPixu(){return cm;}()) + (fu" ascii
    $s9  = "(){return Mmu;}()) + (Grsbi) + (function qdK(){return uhCIq;}()) + (function LPBI(){return gsKbX;}()) + (function CPsq(){return " ascii
    $s10 = "on cqHj(){return r;}()) + (function LpsH(){return PpnKE;}())] = 0;RXh[(function dmE(){return b;}()) + (function eM(){return B1;}" ascii
    $s11 = ") + (Y0) + (function Zo(){return N0;}())] = 1;RXh[(function MbYPg(){return lv;}()) + (MrM)](gOk[(function oUUl(){return UU;}()) " ascii
    $s12 = "rtlQK(){return JFT;}()) + (function sUKV(){return N;}()) + (function dmI(){return zctf;}()) + (GvS) + (BDEc) + (xChia);};functio" ascii
    $s13 = "+ (function spdX(){return ZZWSu;}()) + (function rg(){return N1;}()) + (function pPZCZ(){return Xwbjj;}())]);RXh[(YIZ) + (functi" ascii
    $s14 = "{return T1;}())]((function uZF(){return wqCPc;}()) + (function ky(){return Rn;}())) + (Y) + (oxstP) + (NGkLo) + (JaiSa) + (funct" ascii
    $s15 = "aLTAt;}()) + (ohtqc), false);gOk[(function uzcMM(){return eV;}()) + (function oXgD(){return BPAyN;}())]();while (gOk[(function z" ascii
    $s16 = "return Fxs;}())]();var pRWsV = Tyr[(function KUaDW(){return wSbxX;}()) + (function pyZi(){return GiLYm;}()) + (sBHLK) + (functio" ascii
    $s17 = "turn zix;}()) + (function Fc(){return oTmC;}()) + QhZ ? (function vyjz(){return B2;}()) + (function oQHIm(){return ir;}()) + (fu" ascii
    $s18 = "(function t(){return Fxs;}())]();var SjxmU = Tyr[(function lmcV(){return wSbxX;}()) + (function T0(){return GiLYm;}()) + (functi" ascii
    $s19 = "o;}()) + (SuiA) + (function X(){return eFUy;}()) + (function Dk(){return TIxz;}()) + (function G(){return Fq;}()) + (function oN" ascii
    $s20 = "wm(){return Fo;}()) + (function J(){return UWNpu;}()) + (function MwChv(){return pO;}()) + (NSB) + (function gdAfY(){return vX0;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}