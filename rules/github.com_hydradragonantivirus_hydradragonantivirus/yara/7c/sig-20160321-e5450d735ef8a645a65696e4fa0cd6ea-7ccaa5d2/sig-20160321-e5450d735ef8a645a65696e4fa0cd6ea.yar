rule sig_20160321_e5450d735ef8a645a65696e4fa0cd6ea {
  meta:
    description = "datamaliciousorder - file 20160321_e5450d735ef8a645a65696e4fa0cd6ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "876f9ec7015306a835c3a33ac824ce99e40e811d05b23ce0dbe08761f0bda89a"

  strings:
    $s1  = "function CUAD(bPTg){return bPTg;};function MVd(lypC){return lypC;};var MFZpc = \"2\";var iwtx = \"8\\x316\";var aCT = \"21\\x383" ascii
    $s2  = "function sxY(){return N;}()) + KN + e(ZvTjE)]();WScript[EhEBH](frEcq());var RHvv = new this[(function wC(){return t;}())]();var " ascii
    $s3  = "p = RHvv[pyAhz(ag) + U + (function nSC(){return N;}()) + gc(KN) + (function gUu(){return ZvTjE;}())]();WScript[qN0(EhEBH)](frEcq" ascii
    $s4  = "s = \"\\x6a\";var IeDu = \"\\x74eOb\";var f0 = \"\\x43rea\";var rZGnl = function JkGWg() {return WScript[f0 + IeDu + wfgs(yDRLs)" ascii
    $s5  = "unction u0(){return Yb;}()); n = Gp(); Vpw = WScript[f0 + (function GI(){return IeDu;}()) + (function M(){return yDRLs;}()) + (f" ascii
    $s6  = "Ee(){return Jcs;}()) + (function xDHU(){return C;}()) + jjsZ(gDEk)] < 4 ) {WScript[(function g(){return EhEBH;}())](frEcq() * 10" ascii
    $s7  = "), rF(JgnKE) + oW(uIsrD) + L0(FTPx) + (function xqS(){return xjnTv;}()) + (function KjK(){return nDU;}()) + (function PsT(){retu" ascii
    $s8  = "xVDi() != 0){f = true;yolH = true;break;}}function iuh() {return f && yolH;};if (iuh()){I = rZGnl[Kj + (function JH(){return iQe" ascii
    $s9  = ")};s = false;} catch(e){};}AQKh = WScript[yLr()](zxAxt(dAB) + (function EivMB(){return e0;}()) + (function K(){return EzMt;}()) " ascii
    $s10 = "Tv = nBT[\"charA\\x74\"](2);var FTPx = \"\\x73ia\";var uIsrD = \"p://\";var JgnKE = \"ht\\x74\";var nNX = \"GET\";function HXiFF" ascii
    $s11 = ") + Xzgnh](IJndq + zLLt + Ie(Bjq)) + (function u(){return JPQgq;}()) + cwlgk(DDgP) + Ad(Njw) + (function F(){return YX;}()) + (f" ascii
    $s12 = "+ ZEk(ihEl) + bc(CU) + (function dxblP(){return kI;}()) + r(X0) + BU0(O0) + PjqH + f ? fqHo(abqUo) + IKpO(eH) + (function gjncK(" ascii
    $s13 = "var a = \"Q\";a = VxHLp(zYDp, p);return VxHLp(FrRf, a);}var f = false;var yolH = false;for (var T = 0; T < frEcq() * 1; T++){if " ascii
    $s14 = "nction frEcq(){return 22;};function IxVDi(){var RHvv = new this[(function x(){return t;}())]();var TJtsL = RHvv[FFVg(ag) + U + (" ascii
    $s15 = "As;}()) + (function WS(){return te;}()));}();function UyIvN(LdGZ){rZGnl[(function ZHZp(){return bZf;}())](LdGZ, 0, 0);};function" ascii
    $s16 = "){return iBjJ;}()) : (function y0(){return aCT;}()) + CUAD(iwtx) + MVd(MFZpc);}" fullword ascii
    $s17 = "rn LvgpO;}()) + (function c(){return BCME;}()) + (function X(){return AbAwf;}()) + (function ovnZ(){return qx;}()) + XZJ, false)" ascii
    $s18 = "OH)] = 0;AQKh[(function fma(){return M1;}()) + df + u1(ERU) + IMcK](I, 2 );AQKh[g0 + (function n0(){return ngJbd;}()) + (functio" ascii
    $s19 = ";Vpw[(function qf(){return bIlM;}()) + (function O(){return fCf;}())]();while (Vpw[(function XpSi(){return ZXj;}()) + (function " ascii
    $s20 = "tion fK(){return Kj0;}())](Vpw[(function DpGol(){return gqcC;}()) + S(eh) + M0(ULYQ)]);AQKh[tiM(pCLEs) + dGLH(qPK) + FYFQ + RfD(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}