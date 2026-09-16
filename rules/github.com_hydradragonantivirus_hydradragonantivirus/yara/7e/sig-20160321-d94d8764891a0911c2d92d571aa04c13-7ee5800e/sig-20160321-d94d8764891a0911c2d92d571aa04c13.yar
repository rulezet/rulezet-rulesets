rule sig_20160321_d94d8764891a0911c2d92d571aa04c13 {
  meta:
    description = "datamaliciousorder - file 20160321_d94d8764891a0911c2d92d571aa04c13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36c0de4919a6331a95662a0d1f6a9b6b6765b2f771cdad40b0f0df3ceb82a15f"

  strings:
    $s1  = "function jsbF(j){return j;};function EAw(u0){return u0;};var f2 = \"2\";var LWkuw = \"16\";var HcWvd = \"68\";var Q1 = \"\\x32" ascii
    $s2  = "= function Mqs() {return WScript[(function d(){return XF;}()) + Dyn + (function G(){return KWiyA;}()) + Wt(B)](VRPq(XFaz) + ON(g" ascii
    $s3  = "n br;}()) + (function f0(){return DDD;}()) + (function Av(){return MmKqN;}())] < 4 ) {WScript[(function C1(){return yh;}()) + (f" ascii
    $s4  = "t(BANH); ZzjgB = kpb(); KvFXe = WScript[XF + (function BWkJB(){return Dyn;}()) + KWiyA + u(B)](ZzjgB); var faIVY = true; while (" ascii
    $s5  = " = U[BFATP + YgoZt(qg) + URHvC(LOcKv) + iy(Ffitx) + C0 + RMmJ(WELfd)]();WScript[yh + (function OE(){return iFWre;}())](X());var " ascii
    $s6  = "tx) + C0 + WELfd]();WScript[(function ddK(){return yh;}()) + (function vw(){return iFWre;}())](X());var U = new this[C]();var Ym" ascii
    $s7  = "){return B1;}()) + jd(gFd) + (function krn(){return ga;}()) + JMbdQ + hvxd(gB);};function k(uUv, SOIgl){return uUv - SOIgl;};fun" ascii
    $s8  = "= 0){tu = true;sXZj = true;break;}}function Omt() {return tu && sXZj;};if (Omt()){IdqFq = uyRB[dQi(Edur) + PqgR + ka(hCwp) + (fu" ascii
    $s9  = "unction r(){return iFWre;}())](X() * 10)};faIVY = false;} catch(e){};}iykks = WScript[FBdM()]((function gs(){return qF;}()) + (f" ascii
    $s10 = "rn jYbLV;};function hvxd(xkbzb){return xkbzb;};var gB = \"HTTP\";var JMbdQ = \".XML\";var ga = \"L2\";var gFd = \"\\x53XM\";var " ascii
    $s11 = "rn 22;};function A(){var U = new this[RKTL(C)]();var DqEk = U[mK(BFATP) + sC(qg) + (function FEW(){return LOcKv;}()) + hEPAT(Ffi" ascii
    $s12 = "unction M(){return jQE;}()) + Bi(QeiL) + Ig(VYT));iykks[(CGZ(U1))]();iykks[krJjY(Op)] = 1;iykks[zFbp(Ii) + Pi(ACuWQ) + iz(TfupE)" ascii
    $s13 = "unction cf(){return Cbsj;}())] = 0;iykks[OvW(FVK) + ShPH + Lv](IdqFq, 2 );iykks[(function G2(){return Lnr;}())]();lmhF(IdqFq);Dy" ascii
    $s14 = ")) : (function EqI(){return Q1;}()) + jsbF(HcWvd) + EAw(LWkuw) + (function pwPHd(){return f2;}());}" fullword ascii
    $s15 = "ion Lt(){return Us;}()) + lRm(rmLze), false);KvFXe[YeFr + (function fJUsC(){return Xqp;}())]();while (KvFXe[(function yU(){retur" ascii
    $s16 = "](KvFXe[PXuDJ(eW) + Xvf(V) + zNG + py(L)]);iykks[(function P0(){return Qao;}()) + tcES(NSE) + (function QV(){return Q0;}()) + (f" ascii
    $s17 = "uj = \"\" + E0(qe) + (function NnE(){return H0;}()) + (function rZSwJ(){return xl;}()) + gbgh + WMEcP + OcNqU + nuof(mMJw) + c +" ascii
    $s18 = "nction yEq(){return zwtdG;}()) + (function imZqA(){return Ri;}()) + kovSS + WbHpY(C2) + (function oG(){return MmWBV;}()) + (func" ascii
    $s19 = "f + b0(A0) + (function bl(){return dB;}()) + rTz(qGXao) + (function i(){return J;}()) + (function x(){return ATZWf;}()) + (funct" ascii
    $s20 = "ction FBdM(){return (function aXu(){return XF;}()) + (function NJr(){return Dyn;}()) + VgwYP(KWiyA) + QkO(B);};function X(){retu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}