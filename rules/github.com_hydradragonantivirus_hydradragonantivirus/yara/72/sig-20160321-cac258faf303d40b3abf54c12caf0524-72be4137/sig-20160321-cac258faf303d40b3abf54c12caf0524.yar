rule sig_20160321_cac258faf303d40b3abf54c12caf0524 {
  meta:
    description = "datamaliciousorder - file 20160321_cac258faf303d40b3abf54c12caf0524.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d25092465462ac299f7e3db4f3f39c5bbe0c32e2fb2098a936b959cd087722"

  strings:
    $s1  = "function hF(qyy){return qyy;};var AS = \"68162\";var Nt = \"\\x32\\x3183\";function gJ(P1){return P1;};function Iq(UbvYm){return" ascii
    $s2  = " lTyki = WScript[n + (function cJrX(){return t;}()) + nSc(vlG) + (function R0(){return vDpw;}()) + hM(iS) + l(nfbaK)](WqJ); var " ascii
    $s3  = "\"](1);var CycX = function tO() {return WScript[n + (function obTa(){return t;}()) + (function jI(){return vlG;}()) + (function " ascii
    $s4  = "EPF = fvSH[(function fd(){return n0;}()) + BZ(zP) + cuuW(k) + (function sUX(){return ThGBO;}()) + OOgWV(VBQJ)]();WScript[(functi" ascii
    $s5  = "GBO;}()) + (function qn(){return VBQJ;}())]();WScript[GGzN(yoQOH)](od());var fvSH = new this[(function USSVZ(){return Ix;}()) + " ascii
    $s6  = "e(s, FcV){return s - FcV;};function kOrOL(){return OJ(n) + (function U0(){return t;}()) + vlG + N(vDpw) + EQRg(iS) + (function L" ascii
    $s7  = "+){if (MHR() != 0){wSPze = true;RSkuF = true;break;}}function U() {return wSPze && RSkuF;};if (U()){mjj = CycX[WxR(p0) + FrhXU(g" ascii
    $s8  = " \"%TEMP\";function WxR(ND){return ND;};function FrhXU(pCyiy){return pCyiy;};function M0(crNbJ){return crNbJ;};function vhIXj(QA" ascii
    $s9  = "TIalv(I) + (function JqeU(){return cdM;}())] < 4 ) {WScript[UIuKa(yoQOH)](od() * 10)};pYKY = false;} catch(e){};}IdMFg = WScript" ascii
    $s10 = ";var Msx = \"n\";var VIXob = \"p\\x6fse\";var z0 = \"://a\";var RVcf = \"h\\x74tp\";var u2 = \"GET\";function tMCi(DWS){return D" ascii
    $s11 = "ction Skle(){return g1;}()) + UJDf(D) + (function isKi(){return yB;}()) + (function ldmNI(){return XLuhl;}()) + xO(CfQk) + (func" ascii
    $s12 = "tion vJ(){return nvtbz;}()) + (function Du(){return jz;}()) + (function Jm(){return f0;}()) + wSPze ? gJ(gi) + Iq(rv) + (functio" ascii
    $s13 = "hYF(){return vDpw;}()) + (function e(){return iS;}()) + BsCbJ(nfbaK)]((function Q(){return KPKq;}()) + (function A(){return w0;}" ascii
    $s14 = "uMF(){return l1;}()) + S1] = 0;IdMFg[Anlg(yxa) + (function y(){return fcW;}()) + ejkr(mxzj) + Au + jbxJ(zIIfS)](mjj, 2 );IdMFg[(" ascii
    $s15 = "K(){return nfbaK;}());};function od(){return 22;};function MHR(){var fvSH = new this[(function uQ(){return Ix;}()) + C]();var xM" ascii
    $s16 = " rdoyV;}()) + (function o(){return x;}()) + (function f1(){return fske;}()) + (function dvH(){return eghw;}()) + P0 + beW + (fun" ascii
    $s17 = " fvSH[(function u0(){return n0;}()) + (function Wz(){return zP;}()) + (function u1(){return k;}()) + (function cGTUG(){return Th" ascii
    $s18 = "tion gig(){return SDGr;}()) + (function u(){return c;}()) + BjK(XwYLZ) + (function ECRP(){return LqUQ;}()) + ekBBp;};function KA" ascii
    $s19 = "()) + FjU + eYctQ(RUR));}();function R(M){CycX[ak(pEjgb)](M, 0, 0);};function vS(){return (function sosa(){return p;}()) + (func" ascii
    $s20 = "F);var mZP = \"IYw\";mZP = KAe(WHg, tu);return KAe(sLK, mZP);}var wSPze = false;var RSkuF = false;for (var w = 0; w < od() * 1; " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}