rule sig_20160318_76a0984615abdb11c974bafb208386c9 {
  meta:
    description = "datamaliciousorder - file 20160318_76a0984615abdb11c974bafb208386c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d4882ea731cf0f9b723e7a90f5a60af6f41e0e88b3ec1a03a3a7e4919beaef4"

  strings:
    $x1  = "var LrWsX = \"6bMB!WFPV8\"[\"charAt\"](4);var Se = \"ag\\x61in\";var ZF = \"ry \";var urAj = \", t\";var g = \"ase\";var ric = " ascii
    $s2  = "WScript[gEAHz()]((grUc) + (function tAZgB(){return VYt;}()) + (function vrvPw(){return QQN;}()));siW[((function JNR(){return hJi" ascii
    $s3  = "+ (function ic(){return Jj;}())] < 4 ) {WScript[(function jJ(){return fLTO;}()) + (function l(){return B;}())](z() * 10)};siW = " ascii
    $s4  = "){return W1;}()) + (function hIK(){return O;}()) + (iZtZQ) + (function uFdz(){return neCI;}());}else{WScript.Echo((function Jr()" ascii
    $s5  = " = \"Cre\";var e = function XqRwD() {return WScript[(cDuNf) + (h) + (SYv) + (function j0(){return qDbVN;}()) + (function y(){ret" ascii
    $s6  = "fYXCn) + (function xRlU(){return kWoF;}()) + (function Bm(){return L;}()) + (function P(){return uTFdJ;}())]();WScript[(function" ascii
    $s7  = "J)]();WScript[(function sHmd(){return fLTO;}()) + (function QTqBt(){return B;}())](z());var qU = new this[(tmQ)]();var ju = qU[(" ascii
    $s8  = " t(){return xROii;}());};function EVTnK(AY, d){return AY - d;};function gEAHz(){return (function qFG(){return cDuNf;}()) + (func" ascii
    $s9  = "())] = 0;siW[(function sT(){return LS;}()) + (YeaK) + (GPolj) + (nphE)](WIrBS, 2 );siW[(function vU(){return L0;}()) + (function" ascii
    $s10 = " + (function k(){return q0;}()) + (function zJGI(){return ha;}()) + (function knmX(){return codx;}()) + (function vSO(){return h" ascii
    $s11 = ");}();function u(hbyNQ){e[(function WZ(){return W;}()) + (function rv(){return PmN;}())](hbyNQ, 0, 0);};function bqHcD(){return " ascii
    $s12 = "alse;for (var wQUtZ = 0; wQUtZ < z() * 1; wQUtZ++){if (WqZGJ() != 0){pKNye = true;z0 = true;break;}}function x() {return pKNye &" ascii
    $s13 = "qr;}())]((function NkPfE(){return Zg;}()) + (function Wkd(){return lCm;}())) + (function qSSip(){return kXWnk;}()) + (function t" ascii
    $s14 = "turn gvHej;}())]();while (rc[(function HJpbI(){return Zwu;}()) + (function Db(){return U;}()) + (function K0(){return kJPy;}()) " ascii
    $s15 = "function UfI(){return fYXCn;}()) + (function Xjd(){return kWoF;}()) + (function o(){return L;}()) + (function XGCk(){return uTFd" ascii
    $s16 = "{return ric;}()) + (function MTKt(){return g;}()) + (function FheU(){return urAj;}()) + (function Z(){return ZF;}()) + (Se) + (f" ascii
    $s17 = "tion awUJd(){return h;}()) + (function By(){return SYv;}()) + (function GeUa(){return qDbVN;}()) + (function bLk(){return WqbkG;" ascii
    $s18 = " U0(){return YOsU;}())]();u(WIrBS);E = \"\" + (function UfRap(){return l0;}()) + (function aUJT(){return VJQS;}()) + (function v" ascii
    $s19 = "())]();var YQA = qU[(function aL(){return fYXCn;}()) + (function lavrO(){return kWoF;}()) + (function Yx(){return L;}()) + (uTFd" ascii
    $s20 = "rn qDbVN;}()) + (function A(){return WqbkG;}()) + (Vwwv)](CfUtI);rc[(function KoT(){return hJic;}()) + (GBHFB)]((function TA(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}