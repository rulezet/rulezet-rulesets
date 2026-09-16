rule sig_20160318_8a82296add66b84e4dca86bff3375d79 {
  meta:
    description = "datamaliciousorder - file 20160318_8a82296add66b84e4dca86bff3375d79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb6928c026cbb481437e3d5969cc73f300fa466528fe9545ea54cb8bb702c055"

  strings:
    $s1  = "var eI = \"n!\";var QoeBN = \"ai\";var xua = \"ry \\x61g\";var KJlq = \"e, \\x74\";var GJq = \"Ple\\x61s\";var voShn = \"8\\x316" ascii
    $s2  = "); Y = Zq(); Utm = WScript[(function FXRIo(){return hh;}()) + (wm) + (bgcq) + (function XR(){return K;}()) + (function luM(){ret" ascii
    $s3  = ") + (function guHWB(){return r0;}()) + (function JP(){return TNTW;}()) + (function WOFU(){return deP;}())]();WScript[(function I" ascii
    $s4  = "unction fj(){return deP;}())]();WScript[(function sNlJ(){return T;}()) + (function ME(){return pNMXv;}()) + (function rmT(){retu" ascii
    $s5  = "nction hxo(){return fav;}())]();while (Utm[(m) + (tcvzT) + (function Dgpnw(){return BAr;}())] < 4 ) {WScript[(T) + (pNMXv) + (fu" ascii
    $s6  = " oqo(){return voShn;}());}else{WScript.Echo((function NTqj(){return GJq;}()) + (KJlq) + (function f0(){return xua;}()) + (functi" ascii
    $s7  = "on uaTan() {return WScript[(hh) + (wm) + (function LQ(){return bgcq;}()) + (function HD(){return K;}()) + (function nRn(){return" ascii
    $s8  = "nction y(){return bBKh;}())](bqWZ() * 10)};JFVy = WScript[ZQ()]((function fND(){return ijTm;}()) + (function DE(){return wSpA;}(" ascii
    $s9  = " (function HI(){return BZHsu;}()) + (wg) + (edl);};function Ep(wNmn, nACV){return wNmn - nACV;};function ZQ(){return (function A" ascii
    $s10 = "ut\"[\"charAt\"](4);var cdN = \"\\x62\\x6aec\";var xg = \"\\x4f\";var FEW = \"ate\";var BoOO = \"C\\x72e\";var tIO = \"O.e\\x78" ascii
    $s11 = "xWr(){return hh;}()) + (wm) + (function YjjC(){return bgcq;}()) + (function Id(){return K;}()) + (function TWLjJ(){return MSHF;}" ascii
    $s12 = "(){return TNTW;}()) + (function YxIMh(){return deP;}())]();var yBRk = \"CxiTk\";yBRk = Ep(iVCo, Ur);var Bfmd = \"qbZ\";Bfmd = Ep" ascii
    $s13 = ")) + (function SYT(){return t1;}()) + (function kPGW(){return oS;}()) + (WKPUs));JFVy[((function B(){return MZ;}()) + (function " ascii
    $s14 = ")) + (function PHcT(){return Fn;}()) + (function X0(){return MYc;}()) + (function jWTFG(){return Rnc;}()) + (CH) + (cuBi) + (tIO" ascii
    $s15 = "rn bBKh;}())](bqWZ());var LBt = new this[(EHMa)]();var iVCo = LBt[(function Xv(){return qQ;}()) + (function nb(){return CrvS;}()" ascii
    $s16 = "urn MSHF;}())](Y);Utm[(function XUJz(){return MZ;}()) + (LS)]((function mkxb(){return t0;}()), (function S1(){return mlET;}()) +" ascii
    $s17 = " (function JPLnR(){return hFV;}()) + (function U0(){return LbeWg;}()) + (dHdJ) + (function jT(){return umgmj;}()) + (function V(" ascii
    $s18 = "xTl(){return LS;}()))]();JFVy[(function YA(){return tuOf;}()) + (hJHuM)] = 1;JFVy[(function RncD(){return YvMV;}()) + (function " ascii
    $s19 = "on U(){return PT;}())]((function Pf(){return yniHZ;}()) + (function r1(){return h;}()) + (function RgjfK(){return mBm;}()) + (lh" ascii
    $s20 = "(){return ek;}()) + (function c(){return WkvB;}()) + (function NBs(){return BZAz;}()) + (function vjPY(){return X;}()) + (functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}