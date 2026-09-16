rule sig_20160321_3aaa3545c35d893d440c5ca7713526b9 {
  meta:
    description = "datamaliciousorder - file 20160321_3aaa3545c35d893d440c5ca7713526b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c8c15407a16830d75b1257ce9c07c53bf893892d6a5e559a8103ef1224b033"

  strings:
    $s1  = "var pmBM = \"8162\";var KMCV = \"\\x336\";var gKl = \"2\\x318\";function fiE(MNUO){return MNUO;};var j = \"as\\x64f\";var m2 = " ascii
    $s2  = " cHmMo = \"te\";var m0 = \"\\x72ea\";var Qtsm = yS[\"charAt\"](0);var GAmD = function orm() {return WScript[(function viV(){retu" ascii
    $s3  = "+ eG + (function pEHa(){return TUS;}())]();WScript[(function OPU(){return jMgS;}()) + HXx(fpX)](nM());var U = new this[iJdW(t) +" ascii
    $s4  = "e);D[(function mlo(){return kb;}()) + (function d(){return s;}())]();while (D[Xg + wAVN(oad) + tBr(RN) + Hx] < 4 ) {WScript[(fun" ascii
    $s5  = " PZE(dtf)]();var lbj = U[FbZL(r) + fW + Dy(eG) + i(TUS)]();WScript[jMgS + (function w(){return fpX;}())](nM());var U = new this[" ascii
    $s6  = " + (function dqX(){return BrhXj;}()) + Dj(m1) + LY + (function KPBK(){return JzgI;}()); dpmc = jvd(); D = WScript[(function MLE(" ascii
    $s7  = "nction jvd(){return (function sGE(){return IqOlv;}()) + TG + VDn + LtH;};function kqDk(o, x){return o - x;};function CH(){return" ascii
    $s8  = " = 0; wYx < nM() * 1; wYx++){if (rZ() != 0){AN = true;a = true;break;}}function B() {return AN && a;};if (B()){qX = GAmD[Kqux(LD" ascii
    $s9  = "ction AK(){return jMgS;}()) + QmHrk(fpX)](nM() * 10)};omvcC = false;} catch(e){};}R = WScript[CH()](BBTO(lJO) + cUoF + (function" ascii
    $s10 = "r lJO = \"A\\x44\\x4fDB\";var zMqfm = \"VWpSA\";var O0 = zMqfm[\"charAt\"](2);var ZpMF = \"Sle\\x65\";function wAVN(cLej){return" ascii
    $s11 = "ndAg;};function EGRyR(xDRLD){return xDRLD;};var oEVs = \"SRD7Udv9F7\";var cceo = \"\\x79\";var uF = oEVs[\"charAt\"](5);var tL =" ascii
    $s12 = " z0 = \"9j17Dpk\";var fpX = z0[\"charAt\"](5);var jMgS = \"\\x53lee\";function rEKDS(ac){return ac;};function FbZL(yd){return yd" ascii
    $s13 = "ction tBr(Oyyba){return Oyyba;};var nyTHp = \"hAa\";var Hx = \"ate\";var RN = \"dy\\x73t\";var oad = nyTHp[\"charAt\"](2);var Xg" ascii
    $s14 = "Gk = \"\\x74\\x65\";var vB = ZwQIc[\"charAt\"](0);var sIj = \"\\x44\";function HXx(Au){return Au;};function QmHrk(PFeo){return P" ascii
    $s15 = "){return Qtsm;}()) + (function ruXER(){return m0;}()) + (function RYc(){return cHmMo;}()) + (function wPhfr(){return VzWa;}()) +" ascii
    $s16 = " Qtsm + hGLl(m0) + cHmMo + (function ZH(){return VzWa;}()) + FaE(mRI) + (function z(){return G;}());};function nM(){return 22;};" ascii
    $s17 = ";}()) + m0 + cHmMo + (function sZTuy(){return VzWa;}()) + (function BM(){return mRI;}()) + (function PjeSc(){return G;}())](W + " ascii
    $s18 = "function rZ(){var U = new this[cxgm(t) + (function sBBi(){return dtf;}())]();var g = U[rEKDS(r) + (function x0(){return fW;}()) " ascii
    $s19 = " e(mRI) + cY(G)](dpmc); var omvcC = true; while (omvcC){try {D[ZHCN + ti(kecdw)](G0, PK(Lqxi) + iOzCX + (function v(){return eKc" ascii
    $s20 = "rn cceo;}())]);R[bjm + sGlOV(IcVRY) + (function ANjDo(){return YJq;}())] = 0;R[aV + (function umyCV(){return Hiteg;}()) + Cu](qX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}