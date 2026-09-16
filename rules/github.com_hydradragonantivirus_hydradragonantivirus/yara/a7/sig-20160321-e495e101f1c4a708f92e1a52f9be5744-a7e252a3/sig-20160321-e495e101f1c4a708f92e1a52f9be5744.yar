rule sig_20160321_e495e101f1c4a708f92e1a52f9be5744 {
  meta:
    description = "datamaliciousorder - file 20160321_e495e101f1c4a708f92e1a52f9be5744.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a41715ac9edb6e7f19516d6f0588a210e02f2529ae771c044537fded218df02"

  strings:
    $s1  = " h1 + (function rXpfI(){return z;}()) + o(CHvnH) + (function cEY(){return xUn;}()) + vI]();WScript[(function Mj(){return Hzw;}()" ascii
    $s2  = "ZxeB(){return vI;}())]();WScript[Hzw + (function J(){return cq;}())](qNSxk());var W = new this[QfS + h0(APAXD)]();var E = W[xa +" ascii
    $s3  = ";var kDEWI = \"ea\";var WCnNU = \"Cr\";var Cdbx = function LiqES() {return WScript[eUa(WCnNU) + kDEWI + ViIab + PS + (function U" ascii
    $s4  = "function YO(THKv){return THKv;};var QqcVB = \"2\";var AIbS = \"6\";var mWIr = \"81\";var vqe = \"\\x3218\\x336\";function ZHrSf(" ascii
    $s5  = "n K1(){return jE;}()) + (function Opl(){return DFK;}()) + (function qe(){return Ny;}())] < 4 ) {WScript[hDQCP(Hzw) + cq](qNSxk()" ascii
    $s6  = "eQo) + vB + nSBj(oCFe)) + mKh + (function CZvyC(){return xHg;}()) + yYfb(Xlc) + JiSU + dMsUo; kv = YcjvM(); ktV = WScript[(funct" ascii
    $s7  = "rn x - NiH;};function VM(){return (function qkL(){return WCnNU;}()) + T(kDEWI) + (function ZTSin(){return ViIab;}()) + gB(PS) + " ascii
    $s8  = "() != 0){j = true;F = true;break;}}function zmZf() {return j && F;};if (zmZf()){InN = Cdbx[(function hW(){return KzJ;}()) + (fun" ascii
    $s9  = " * 10)};OsrV = false;} catch(e){};}PklY = WScript[VM()](ONR + tWJay + DpXRM);PklY[((function nhyeP(){return sAe;}()) + (function" ascii
    $s10 = "tion o0(){return xa;}()) + ep(h1) + (function DWuV(){return z;}()) + CHvnH + isA(xUn) + iut(vI)]();var CUTs = \"TEX\";CUTs = OEg" ascii
    $s11 = "(iVps) + j ? (function rDdan(){return j2;}()) + (function r0(){return pcuQ;}()) + ZHrSf(D) + ic : (function mgTA(){return vqe;}(" ascii
    $s12 = "ction yb(){return I;}()) + (function E0(){return VFw;}()) + i0(YwnW) + (function XpH(){return dKy;}()) + Oe(JX) + N + isx](oGmf(" ascii
    $s13 = "(){return nVn;}()) + GE](tXAM(wVPvm) + qXOpD(Be) + Xtg);}();function uzxR(pj){Cdbx[(function t(){return Ogo;}())](pj, 0, 0);};fu" ascii
    $s14 = "nVn + (function vQNX(){return GE;}());};function qNSxk(){return 22;};function gL(){var W = new this[(function qZFhJ(){return QfS" ascii
    $s15 = "GE;}())](kv); var OsrV = true; while (OsrV){try {ktV[(function Jhg(){return sAe;}()) + kt(r)](zii, (function KmzM(){return h2;}(" ascii
    $s16 = ")) + uxZG + XJ + AAzw(je) + N0(YKI) + (function SM(){return lU;}()) + n + (function UQHtj(){return FR;}()) + (function HgY(){ret" ascii
    $s17 = "ion MPPi(){return WCnNU;}()) + j0(kDEWI) + (function yMDgt(){return ViIab;}()) + oPp(PS) + jJdCq(nVn) + (function EDpk(){return " ascii
    $s18 = "urn RhEp;}()) + m(VTol) + (function iJc(){return FgP;}()) + ypf, false);ktV[(function G(){return OoH;}())]();while (ktV[(functio" ascii
    $s19 = "UTs = \"\" + s1(hH) + (function qQe(){return TcCji;}()) + (function nfUA(){return Ba;}()) + (function bVtW(){return HQXCS;}()) +" ascii
    $s20 = "function sxN(){return HTx;}())] = 0;PklY[Lq(ub) + o1(JwwP) + (function ELR(){return gDnn;}()) + (function v(){return il;}())](In" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}