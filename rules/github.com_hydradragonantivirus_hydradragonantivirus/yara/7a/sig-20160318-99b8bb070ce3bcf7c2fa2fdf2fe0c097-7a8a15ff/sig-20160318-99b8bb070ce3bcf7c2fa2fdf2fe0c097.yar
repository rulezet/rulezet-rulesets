rule sig_20160318_99b8bb070ce3bcf7c2fa2fdf2fe0c097 {
  meta:
    description = "datamaliciousorder - file 20160318_99b8bb070ce3bcf7c2fa2fdf2fe0c097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db015f6c5acaad13549b6355fc015fa69754e01b43479ce911b56f4d5c73d102"

  strings:
    $s1  = "var ESq = \"!\";var apmSa = \"a\\x69\\x6e\";var UJYBp = \"\\x79 \\x61g\";var Xwdz = \",\\x20\\x74\\x72\";var POa = \"se\";var HR" ascii
    $s2  = "urn a;}()) + (urbkg) + (gX) + (function Xpd(){return mSpD;}()) + (function XmHOh(){return vdg;}()); YLoc = gmH(); e = WScript[(F" ascii
    $s3  = "(function xhqM(){return hYLuG;}()) + (IgxC) + (function Tl(){return ito;}());}else{WScript.Echo((HR) + (function de(){return POa" ascii
    $s4  = " Qt;}()) + (function k(){return jFIT;}()) + (function VO(){return nz;}())]();WScript[(function I0(){return MVsBI;}()) + (functio" ascii
    $s5  = "z;}()) + (function iQ(){return Qt;}()) + (function RV(){return jFIT;}()) + (nz)]();WScript[(function rNkhv(){return MVsBI;}()) +" ascii
    $s6  = "{return o0;}()) + (function HLr(){return VXUoX;}())] < 4 ) {WScript[(function zpSlh(){return MVsBI;}()) + (function zar(){return" ascii
    $s7  = ") {return WScript[(function Nevi(){return FL;}()) + (function e0(){return LzY;}()) + (function bh(){return Eq;}())]((function T(" ascii
    $s8  = " rJg;}())](fi() * 10)};g = WScript[P()]((function chMB(){return p0;}()) + (function IZslB(){return m1;}()) + (FbzP) + (function " ascii
    $s9  = "return YPFLg;}()) + (function rBws(){return yLO;}());};function C(Y, yiVa){return Y - yiVa;};function P(){return (FL) + (functio" ascii
    $s10 = "< fi() * 1; tPVi++){if (RrIVi() != 0){NJl = true;jyN = true;break;}}function Bk() {return NJl && jyN;};if (Bk()){Anm = jary[(C0)" ascii
    $s11 = "function nX(){return BXnzb;}()) + (iww)](Anm, 2 );g[(function S(){return qMWJ;}())]();upEMI(Anm);Bdf = \"\" + (function R(){retu" ascii
    $s12 = "twzm(){return zG;}()));g[((function weG(){return SW;}()) + (PK))]();g[(function quH(){return P0;}()) + (function wSCt(){return D" ascii
    $s13 = ";}()) + (function fbDgC(){return xRQMV;}()) + (function Jzcl(){return O;}()) + (function b(){return OSFu;}())]((function PWxhR()" ascii
    $s14 = "FIlot(){return aF;}())](N, 0, 0);};function gmH(){return (function WC(){return RQN;}()) + (function IopzJ(){return aQVHD;}()) + " ascii
    $s15 = " + (function zloU(){return IRhrx;}()) + (function O0(){return yD;}()) + (function RU(){return L0;}()) + (function F(){return KTY" ascii
    $s16 = "{return lgG;}()) + (SDzT) + (uEtf) + (function SeOY(){return JFmt;}())) + (function svjz(){return Su;}()) + (function DbHZ(){ret" ascii
    $s17 = "jPMn;}())] = 1;g[(function Q0(){return cs;}()) + (function bTC(){return UMI;}())](e[(function o1(){return ldJ;}()) + (xtjGl) + (" ascii
    $s18 = "Zrj(){return gRf;}())]();var Lp = m[(function jtrfX(){return gfSQ;}()) + (function vMf(){return kz;}()) + (function xFu(){return" ascii
    $s19 = "n jq(){return LzY;}()) + (function wCf(){return Eq;}());};function fi(){return 22;};function RrIVi(){var m = new this[(function " ascii
    $s20 = "){return mlC;}()) + (m0) + (function M(){return G;}()) + (function giVfs(){return oj;}()));}();function upEMI(N){jary[(function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}