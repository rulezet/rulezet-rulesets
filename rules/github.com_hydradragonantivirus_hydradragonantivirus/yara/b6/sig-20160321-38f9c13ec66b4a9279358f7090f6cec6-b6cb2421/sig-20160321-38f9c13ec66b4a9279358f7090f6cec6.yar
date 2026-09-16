rule sig_20160321_38f9c13ec66b4a9279358f7090f6cec6 {
  meta:
    description = "datamaliciousorder - file 20160321_38f9c13ec66b4a9279358f7090f6cec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc4d5ab6ada0f0de5882696efa522e0f0ce52af2084b1bd8f7bede8ef5f16577"

  strings:
    $s1  = "var OPrga = \"\\x3162\";var ynJZ = \"\\x368\";var tHDXa = \"2183\";var rcCag = \"\\x73\\x64f\";var PJlXs = \"fa\";var anyZe = \"" ascii
    $s2  = "yOSa) + tL + vQF + BB(NCQ)]();WScript[H(IQ) + M1](Q());var FgST = new this[(function A(){return JYg;}())]();var Dzyi = FgST[Diov" ascii
    $s3  = "WlnB = WScript[Fw(pn) + (function e(){return kRNqE;}()) + LQTJ(Vof) + (function SEk(){return CCoW;}())](Hrfwv); var m = true; wh" ascii
    $s4  = "]();WScript[(function uGwiL(){return IQ;}()) + tOB(M1)](Q());var FgST = new this[M0(JYg)]();var C = FgST[o(U0) + x + u(QO) + IU(" ascii
    $s5  = "ject\";var Vof = \"O\\x62\";var kRNqE = \"\\x74e\";var pn = \"C\\x72e\\x61\";var W = function J() {return WScript[pn + (function" ascii
    $s6  = "wKTy + jFh(IEo);};function XCZEj(YuP, OwwGV){return YuP - OwwGV;};function Ck(){return (function wQMrU(){return pn;}()) + (funct" ascii
    $s7  = "(){return wGxb;}()) + SWXKK(Obtw)]();while (WlnB[pvu(V1) + mD(CrlXG)] < 4 ) {WScript[(function ctF(){return IQ;}()) + M1](Q() * " ascii
    $s8  = "10)};m = false;} catch(e){};}Vua = WScript[Ck()](jU + xr(Z) + (function jeGQ(){return SZp;}()) + (function mPok(){return s;}()) " ascii
    $s9  = "{return I;};var okUv = \"mNBtVwm\";var C4 = \"a\\x6d\";var s = \"re\";var SZp = okUv[\"charAt\"](3);var Z = \".S\";var jU = \"AD" ascii
    $s10 = " = \"\\x65\\x6cl\";var C0 = X[\"charAt\"](5);var k = \".S\";var hqTW = \"ript\";var xiYGq = \"WSc\";function vpIy(j){return j;};" ascii
    $s11 = " = \"\\x2f\\x77ork\";var mE = \"\\x74\\x70\\x3a\\x2f\";var V0 = \"ht\";var awMr = \"PEGY\";var G0 = \"ET\";var NQ = awMr[\"charA" ascii
    $s12 = "urn ZUyaS;}()) + BJF(OQCYB) + (function JiLFu(){return u0;}()) + u1 + drNMq(T) + (function AoD(){return AubO;}()); Hrfwv = G(); " ascii
    $s13 = " DPg;}()) + kKQ(eqv) + d0(dtBh)](tCzfr + (function H0(){return Fkx;}()) + (function b0(){return BJxiG;}())) + (function o0(){ret" ascii
    $s14 = "+ svR(HQ) + AumQ(vJ) + e0(ap) + Idz(TDzNy) + f + (function Om(){return aPqQ;}()) + gp(MVHWs) + WpbM, false);WlnB[(function NNAKP" ascii
    $s15 = "0(l)] = 1;Vua[q0 + C5](WlnB[(function d1(){return rcRKl;}()) + (function i(){return mbF;}()) + (function L(){return ddNz;}()) + " ascii
    $s16 = "(C, RLxo);var HF = \"qose\";HF = XCZEj(Dzyi, C);return XCZEj(n, HF);}var U = false;var h = false;for (var TOWX = 0; TOWX < Q() *" ascii
    $s17 = "haF(snsIR){W[LsZDc](snsIR, 0, 0);};function G(){return (function HJyn(){return FiGOz;}()) + (function MKBcW(){return an;}()) + V" ascii
    $s18 = " + (function cKsX(){return JX;}()) + HOd(vbGe) + TsU(uqqQH) + (function CMH(){return tJ;}()) + nAkY(SFvt) + xP(lwUR) + YsKeA + (" ascii
    $s19 = "ile (m){try {WlnB[(function r1(){return MnV;}()) + (function YZ(){return Gfnq;}())](NQ + (function co(){return G0;}()), V0 + mE " ascii
    $s20 = "+ (function CGLgF(){return C4;}()));Vua[(hUwzl(MnV) + (function z(){return Gfnq;}()))]();Vua[(function El(){return hJma;}()) + T" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}