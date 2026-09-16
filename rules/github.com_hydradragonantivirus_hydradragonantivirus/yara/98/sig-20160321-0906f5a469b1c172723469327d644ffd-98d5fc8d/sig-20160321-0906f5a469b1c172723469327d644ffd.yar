rule sig_20160321_0906f5a469b1c172723469327d644ffd {
  meta:
    description = "datamaliciousorder - file 20160321_0906f5a469b1c172723469327d644ffd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac556b4adec389dd9c8808a3d46b47ac72333dfb0c862fb3b91ddf2b6a7e41ef"

  strings:
    $s1  = "function n0(CZm){return CZm;};function SyqxI(u1){return u1;};var Dn = \"2sz\";var t0 = \"162\";var KSDr = \"\\x31\\x38368\";var " ascii
    $s2  = "}())] < 4 ) {WScript[(function WRrF(){return BrRx;}()) + jx(nKg) + (function ZpBHt(){return ezZQ;}())](dQIb() * 10)};R = false;}" ascii
    $s3  = "tyH;}())]();WScript[(function Pe(){return BrRx;}()) + Rsg(nKg) + CJq(ezZQ)](dQIb());var FLsc = new this[D(jD) + skUM(KcjN)]();va" ascii
    $s4  = "b\\x6a\";var kAL = \"a\\x74\\x65\";var FY = \"C\\x72e\";var dK = function PGaZ() {return WScript[cbv(FY) + kAL + vQ(swi) + KQnO(" ascii
    $s5  = "function nWO(){return MedH;}())](zEUR(Xi) + FmbY(z)) + yweGU + pMgBT(u) + wbl(f) + K(BGK); TxYoX = dhx(); Cgs = WScript[FY + Tdx" ascii
    $s6  = "turn rVdbu;}()) + oEy + btyH]();WScript[(function v0(){return BrRx;}()) + (function MUa(){return nKg;}()) + ezZQ](dQIb());var FL" ascii
    $s7  = "on oMfh(){return TtDCn;}()) + iay + XRXs(sat) + (function Cdw(){return WPXB;}());};function mdLX(oQngy, aieG){return oQngy - aie" ascii
    $s8  = " != 0){OBA = true;RQ = true;break;}}function oWznU() {return OBA && RQ;};if (oWznU()){KY = dK[(function LW(){return NF;}()) + (f" ascii
    $s9  = "var m0 = \"w\\x77\\x77\\x2e\\x64\";var yarE = \"/\";var kd = xoW[\"char\\x41t\"](0);var zOb = \"tp:\";var nXPu = \"ht\";var KCc " ascii
    $s10 = " catch(e){};}KsXoM = WScript[hmxp()](RGtc(VmDo) + HStDZ + (function lFXxe(){return MYbN;}()) + (function O0(){return QZsZR;}()) " ascii
    $s11 = "KsXoM[b + RTC(FXPOD) + (function aF(){return soAFu;}())] = 0;KsXoM[(function nMNL(){return gFW;}()) + ju](KY, 2 );KsXoM[(functio" ascii
    $s12 = "U(kAL) + s0(swi) + Awd](TxYoX); var R = true; while (R){try {Cgs[rF(haR)](XUny + UuY, (function jzbz(){return nXPu;}()) + zOb + " ascii
    $s13 = "xM\";YvM = mdLX(bFjK, kyNli);return mdLX(ry, YvM);}var OBA = false;var RQ = false;for (var v = 0; v < dQIb() * 1; v++){if (YHRE(" ascii
    $s14 = ") + rVdbu + (function eSiI(){return oEy;}()) + (function xwZ(){return btyH;}())]();var ry = \"n\";ry = mdLX(kyNli, Zx);var YvM =" ascii
    $s15 = "r kyNli = FLsc[(function Uvmi(){return llVaE;}()) + (function jMr(){return qKIO;}()) + DYrz(l1) + xHKs(QQ) + (function EEiC(){re" ascii
    $s16 = " vcjwJ(){return c;}()), false);Cgs[gLj + g1]();while (Cgs[(function oPG(){return QAOVn;}()) + pJj + (function wX(){return iFFuU;" ascii
    $s17 = " pAyZR(){return rNUV;}()) + (function GGIob(){return oEV;}()) + BHYiP + R0(m1) + (function Vlqg(){return GnhCG;}()) + j(sOXdw) +" ascii
    $s18 = "G;};function hmxp(){return (function qC(){return FY;}()) + fwcl(kAL) + (function s(){return swi;}()) + l(Awd);};function dQIb(){" ascii
    $s19 = "+ Ylda);KsXoM[((function C0(){return haR;}()))]();KsXoM[(function bVxJ(){return lbU;}())] = 1;KsXoM[(function Gd(){return jp;}()" ascii
    $s20 = "n Y0(){return eko;}())]();LKAr(KY);ry = \"\" + zuTN(IM) + elCfo + M0 + (function VJbLT(){return hZ;}()) + sQX(EJzzq) + cgkZ(tv) " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}