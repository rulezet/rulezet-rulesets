rule sig_20160318_4b8f68ca87f2d7af40768e6464f4f531 {
  meta:
    description = "datamaliciousorder - file 20160318_4b8f68ca87f2d7af40768e6464f4f531.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c9cd37f3ebd1f695d1e452acd27063e7337ea532b5c50576b8e13faf32a653"

  strings:
    $s1  = "var zYE = \"in!\";var lRJX = \"\\x61ga\";var u1 = \"tr\\x79 \";var QiXgr = \"\\x2c\\x20\";var qtBb = \"eas\\x65\";var Qb = \"Pl" ascii
    $s2  = ";WScript[(function ofj(){return zLnBF;}()) + (function dYnS(){return hsKHb;}()) + (h2)](id());var i = new this[(pNTYh) + (functi" ascii
    $s3  = "L;}()) + (function HkLjO(){return M2;}()) + (function aD(){return tScgJ;}());}else{WScript.Echo((function GOu(){return Qb;}()) +" ascii
    $s4  = "n QG(){return NhTv;}()) + (function OZaS(){return MYPP;}()) + (function fcgMi(){return oIhRZ;}())] < 4 ) {WScript[(function g0()" ascii
    $s5  = " Wxi(){return NC;}()); a = pAniP(); wLhP = WScript[(os) + (VE) + (function Vto(){return TA;}())](a);wLhP[(function R(){return D;" ascii
    $s6  = " VE = \"\\x65Ob\";var os = \"Cr\\x65a\\x74\";var iTKt = function gsicp() {return WScript[(function x(){return os;}()) + (functio" ascii
    $s7  = "{return zLnBF;}()) + (hsKHb) + (h2)](id() * 10)};Qa = WScript[NAjIP()]((function kf(){return E1;}()) + (eFVNI) + (function mbjOz" ascii
    $s8  = "(function Aob(){return FRlqW;}()) + (function u(){return PZyi;}()) + (ds)]();WScript[(zLnBF) + (function dbH(){return hsKHb;}())" ascii
    $s9  = "ion h(){return pzspP;}());};function tkjkG(wsxbH, M){return wsxbH - M;};function NAjIP(){return (function a0(){return os;}()) + " ascii
    $s10 = "n CMV() {return MqRT && f;};if (CMV()){EmkKd = iTKt[(function K(){return m;}()) + (fQH) + (function SftuY(){return zwa;}()) + (f" ascii
    $s11 = "unction T(){return ezjLR;}()) + (function c1(){return E;}()) + (function TWu(){return yA0;}()) + (function E0(){return oAeRO;}()" ascii
    $s12 = "(){return DW;}()) + (BPJKP));Qa[((D) + (r))]();Qa[(function CYIVf(){return KOq;}())] = 1;Qa[(YS) + (function D0(){return HPBl;}(" ascii
    $s13 = ";}())](EmkKd, 2 );Qa[(function JjtM(){return Npw;}()) + (function jvWSk(){return X0;}())]();z(EmkKd);F = \"\" + (function gW(){r" ascii
    $s14 = "n OPibj(){return GQHO;}()) + (function ittl(){return zGpJ;}()) + (GCvi) + (function o0(){return KauXe;}()) + (pdEnd) + (function" ascii
    $s15 = "}()) + (function QN(){return ixctc;}()) + (function OFEY(){return wdTT;}()) + (function N(){return vBsUx;}()) + (YB) + MqRT ? (f" ascii
    $s16 = "(VE) + (function pIYbM(){return TA;}());};function id(){return 22;};function aFW(){var i = new this[(function cKPl(){return pNTY" ascii
    $s17 = "(NOBM) + (function n(){return H;}()) + (function x0(){return q;}()) + (function MNXC(){return F1;}()) + (function s(){return iT;" ascii
    $s18 = "Dh(){return IFrj;}()) + (Ye) + (function MvE(){return M0;}()) + (function B(){return NCyC;}()) + (function BC(){return tecU;}())" ascii
    $s19 = " (qtBb) + (function ObmS(){return QiXgr;}()) + (function J0(){return u1;}()) + (function UvEZ(){return lRJX;}()) + (function wbR" ascii
    $s20 = "}()) + (r)]((bwx) + (P), (hd) + (function M1(){return FnZP;}()) + (TvlF) + (function sV(){return Sotv;}()) + (DYW) + (function y" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}