rule sig_20160318_0d762b8f61a662cec7a321d648c4640b {
  meta:
    description = "datamaliciousorder - file 20160318_0d762b8f61a662cec7a321d648c4640b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e631ecb6aa7d2b8e64b7da9ba55c7d771b58a86ed83a93bd3af4d6d6030e88b4"

  strings:
    $s1  = "var Z3 = \"a\\x69n!\";var t = \"ry \\x61g\";var AOa = \"e\\x2c\\x20t\";var ADKYc = \"as\";var RKjai = \"eeu\"[\"charAt\"](1);var" ascii
    $s2  = "jei = \"TEMP%\";var iVh = \"C6fM2%\"[\"charAt\"](5);var gvw = \"gs\";var P = \"\\x72in\";var EyY = \"n\\x74\\x53t\";var D = \"me" ascii
    $s3  = "(){return MJMoy;}())](Tl() * 10)};aRB = WScript[TvnJ()]((function sbO(){return bw;}()) + (function Z2(){return vHyP;}()) + (func" ascii
    $s4  = "q(){return Xxu;}()) + (function NJP(){return Vfkqu;}()) + (Meo)] < 4 ) {WScript[(function Kmd(){return eG;}()) + (function IhkFl" ascii
    $s5  = ";WScript[(function uGFNh(){return eG;}()) + (function ZSnY(){return MJMoy;}())](Tl());var DPG = new this[(function Uxq(){return " ascii
    $s6  = "eturn QmI;}()) + (ER); WEJx = Z(); qAcV = WScript[(function Xp(){return HiIG;}()) + (function d(){return YvR;}()) + (FOoFm)](WEJ" ascii
    $s7  = "= \"\\x43r\\x65\\x61t\";var q = function dJ() {return WScript[(function fFqiW(){return HiIG;}()) + (function mj(){return YvR;}()" ascii
    $s8  = "n dLsG(){return w;}()) + (x0);};function iGIGp(X, RF){return X - RF;};function TvnJ(){return (function gKtHw(){return HiIG;}()) " ascii
    $s9  = "OukO = true;break;}}function YSe() {return kn && FOukO;};if (YSe()){IkElB = q[(function oLZ(){return RAO;}()) + (sc) + (function" ascii
    $s10 = "ipt.Echo((function Bkwbo(){return xMD;}()) + (RKjai) + (function fr(){return ADKYc;}()) + (AOa) + (function WmH(){return t;}()) " ascii
    $s11 = "sEQ(){return FcRLp;}()) + (function KU(){return UBS;}()) + (function bkt(){return bMg;}())]();WScript[(function L(){return eG;}(" ascii
    $s12 = "(){return s;}()) + (function JLUN(){return VPD;}())]();y(IkElB);dTrd = \"\" + (hSMH) + (pC) + (zgzH) + (function sjH(){return WF" ascii
    $s13 = "PWzw;}()) + (function sG(){return XdNQ;}()) + (function zn(){return AL;}()) + (function HzT(){return cPFm;}()));}();function y(T" ascii
    $s14 = "x);qAcV[(z) + (function UQQiB(){return ur;}())]((okM) + (function kExn(){return Ws;}()), (function FsryW(){return gKUAF;}()) + (" ascii
    $s15 = "function ci(){return yoTr;}()) + (function spMfe(){return HBy;}()) + (function DCCLh(){return UuKuv;}()) + (Aqe) + (function SlT" ascii
    $s16 = "function JWt(){return FOoFm;}())]((function SboEK(){return Yxf;}()) + (function h(){return aayg;}()) + (function nLpB(){return X" ascii
    $s17 = "(){return IDEyq;}()) + (function YHPTx(){return OH;}()) + (function swu(){return z0;}()) + (w0) + (function VHd(){return P0;}())" ascii
    $s18 = ") + (function eTNX(){return XUj;}()) + (function Rz(){return DCdnL;}())]);aRB[(function rhAZl(){return aP;}()) + (function d0(){" ascii
    $s19 = ")) + (MJMoy)](Tl());var DPG = new this[(function Z0(){return S;}())]();var TFxff = DPG[(function yYx(){return qTl;}()) + (functi" ascii
    $s20 = " + (function QCfCU(){return yaDJ;}()), false);qAcV[(function MdT(){return noUTE;}()) + (JGLB)]();while (qAcV[(L0) + (function UW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}