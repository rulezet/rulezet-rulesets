rule sig_20160318_eae0ecea21cd2331b2c50e24dbf0d96c {
  meta:
    description = "datamaliciousorder - file 20160318_eae0ecea21cd2331b2c50e24dbf0d96c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea727b48ccd14e438a16b2da5c1c41e8bedc883b81b9135bd2b579847111bee1"

  strings:
    $s1  = "var FpcI = \"hnkfj!7h\"[\"charAt\"](5);var qFCOX = \"n\";var bILc = \"\\x61\\x67ai\";var Qf = \"ry \";var Rism = \"e, t\";var Am" ascii
    $s2  = " + (function nBCt(){return xh;}())] < 4 ) {WScript[(function qyFIw(){return nVOo;}()) + (ZFXVa)](feK() * 10)};zb = WScript[E()](" ascii
    $s3  = "x65O\\x62j\\x65\";var YXBl = \"C\\x72eat\";var e = function GMkNO() {return WScript[(function Odk(){return YXBl;}()) + (function" ascii
    $s4  = "FH) + (function RI(){return vmDX;}()) + (function QKwIA(){return D;}()) + (function vQjZ(){return a;}())]();WScript[(function Vs" ascii
    $s5  = "uW(){return vmDX;}()) + (D) + (function dYe(){return a;}())]();WScript[(function uybq(){return nVOo;}()) + (function RHtJW(){ret" ascii
    $s6  = " kuS;}());}else{WScript.Echo((function Oh(){return Am;}()) + (Rism) + (function MIB(){return Qf;}()) + (function Farar(){return " ascii
    $s7  = "69\\x74\";var lozwh = \"PRJH/HRJn\"[\"charAt\"](4);var GAzE = \"\\x3a/\";var HaimI = \"h\\x74\\x74p\";var LUA = \"GET\";var IadY" ascii
    $s8  = "= WScript[(function asOw(){return YXBl;}()) + (function Wx(){return hLEXt;}()) + (function l(){return shfn;}())](wLP);ic[(functi" ascii
    $s9  = ") + (cbDz);};function wymU(WBYnv, fWdM){return WBYnv - fWdM;};function E(){return (function ZKR(){return YXBl;}()) + (function T" ascii
    $s10 = "e;for (var bLC = 0; bLC < feK() * 1; bLC++){if (nXYDf() != 0){Mbmxh = true;LZP = true;break;}}function n() {return Mbmxh && LZP;" ascii
    $s11 = "n nWAFj(){return KJ;}()) + (D0) + (function k(){return jCDL;}()) + (function wrban(){return iJHFA;}()) + (BOaY)]((function mrsVU" ascii
    $s12 = "){return NX;}()) + (function nD(){return p;}()) + (function ALD(){return gQ;}()) + (cIq) + (cMaO) + (function V0(){return t;}())" ascii
    $s13 = "tion nXAj(){return M;}()) + (wVg) + (qnEY) + (function dmb(){return NIA;}()) + (function NSNm(){return X0;}()); wLP = nuc(); ic " ascii
    $s14 = "(){return sJfd;}()) + (function fgr(){return XQ;}())]();z(FIih);OkHi = \"\" + (function CbsQv(){return BjvVH;}()) + (function Us" ascii
    $s15 = "};if (n()){FIih = e[(function PEhU(){return yU;}()) + (function nf(){return bRr;}()) + (function ZIFW(){return G;}()) + (functio" ascii
    $s16 = "(){return LXq;}()) + (function xyfF(){return FckB;}())) + (function G0(){return o;}()) + (function gkYb(){return nm;}()) + (func" ascii
    $s17 = "turn ncuK;}()) + (wri)] = 0;zb[(function fqCih(){return RJ;}()) + (a0) + (function T0(){return H;}())](FIih, 2 );zb[(function zy" ascii
    $s18 = "on lY(){return M0;}()) + (function WA(){return IadY;}())]((LUA), (function fHHB(){return HaimI;}()) + (function nuVIm(){return G" ascii
    $s19 = "(){return nVOo;}()) + (ZFXVa)](feK());var vUZ = new this[(function XgM(){return X;}()) + (function N(){return fTtTI;}())]();var " ascii
    $s20 = "(function lhW(){return V;}()) + (function slL(){return hxI;}()) + (gg) + (Ux));zb[((function xEm(){return M0;}()) + (IadY))]();z" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}