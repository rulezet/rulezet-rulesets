rule sig_20160321_8c04575c0f93755235751bb37ed96c6e {
  meta:
    description = "datamaliciousorder - file 20160321_8c04575c0f93755235751bb37ed96c6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8898b81d4d1cfea0f9789c6cbd8818dbf7183a1aa8c7f9403aeb0c20e31975e2"

  strings:
    $s1  = "function pBl(AlwG){return AlwG;};var DrCw = \"7AZiv2nT\";var quLf = \"162\";var M1 = \"18\\x3368\";var BRzT = DrCw[\"char\\x41t" ascii
    $s2  = "(){return SKZv;}()) + (function nrPR(){return oVD;}()); UCmU = dRN(); JKB = WScript[QE + cO(jvOkj) + q + RWQ](UCmU); var t = tru" ascii
    $s3  = "n sKkN;}()) + ibA + LfBw(sKq)] < 4 ) {WScript[(function hY(){return nuj;}()) + (function gsut(){return k;}()) + fr(KJ)](YZdDa() " ascii
    $s4  = "* 10)};t = false;} catch(e){};}Bnq = WScript[IF()]((function FwHEh(){return M0;}()) + Qc(EXIRR) + (function e(){return Ke;}()) +" ascii
    $s5  = " (function pg(){return HKcG;}()) + oyre(Nq) + eevZ(oD0)]();WScript[uDWiJ(nuj) + QI(k) + (function M(){return KJ;}())](YZdDa());v" ascii
    $s6  = "){return HKcG;}()) + Nq + (function pO(){return oD0;}())]();WScript[rE(nuj) + (function CrwQZ(){return k;}()) + enOd(KJ)](YZdDa(" ascii
    $s7  = "ion lSJE() {return WScript[vfr(QE) + Ap(jvOkj) + vO(q) + ZqLaO(RWQ)](DbfBM + (function pK(){return NV;}()) + LLje);}();function " ascii
    $s8  = " bYv(h, ReKWK){return h - ReKWK;};function IF(){return xjfy(QE) + gWnu(jvOkj) + lHp(q) + (function gk(){return RWQ;}());};functi" ascii
    $s9  = " r = 0; r < YZdDa() * 1; r++){if (oD() != 0){V = true;X = true;break;}}function vvUau() {return V && X;};if (vvUau()){p0 = E[ByA" ascii
    $s10 = "w\\x77\\x77\";var wgwbZ = \"p:\\x2f\";var ZdGoq = \"htt\";function l1(Wv){return Wv;};var SSeD = \"\\x47ET\";var azpKE = \"pen\"" ascii
    $s11 = "ar VzZ = new this[gRg + jvaj]();var I = VzZ[u(P0) + (function Yp(){return n;}()) + (function VN(){return Pa;}()) + (function cP(" ascii
    $s12 = "return D;}()) + hnHQa + NGrSV + Z1(tiAK) + KF, false);JKB[(function FPjCe(){return xJyc;}())]();while (JKB[(function PdR(){retur" ascii
    $s13 = "0);X0 = \"\" + (function C(){return OyVXC;}()) + (function Q(){return ZESrj;}()) + i(gbmh) + gD(aHsy) + zl(B) + f0(GNpEK) + Tx +" ascii
    $s14 = "pw + JD(ieG) + (function pQU(){return TdGD;}()) + (function Bb(){return F;}()) + rom + NZQdJ(Lw) + nVA(bqYat) + (function IKJ(){" ascii
    $s15 = "on YZdDa(){return 22;};function oD(){var VzZ = new this[gRg + (function zWGp(){return jvaj;}())]();var SEYQL = VzZ[P0 + n + Pa +" ascii
    $s16 = "));var VzZ = new this[(function T(){return gRg;}()) + jvaj]();var nnH = VzZ[P0 + IWo(n) + Pyv(Pa) + pDOS(HKcG) + z(Nq) + oD0]();" ascii
    $s17 = "O(OvF){E[knJSD(XLBq)](OvF, 0, 0);};function dRN(){return KuS + ohX + Oj + VKtbA(KEiss) + (function I0(){return f;}());};function" ascii
    $s18 = "1;Bnq[(function zG(){return JslzB;}()) + QiG(Cl)](JKB[(function hlr(){return oaKG;}()) + LC0(hMJ) + apH(J)]);Bnq[osiza(KyF) + I1" ascii
    $s19 = "function Zos(){return VY;}()) + A0(MjfJ) + Kya + Hb(dHrhy) + (function daNuU(){return E0;}()) + (function QDhn(){return ONxYA;}(" ascii
    $s20 = "oU + X2 + lGufO(YBar) + (function yKX(){return CZxXs;}()) + l(hwDOc) + BKc(LC) + (function ki(){return MS;}()) + jPQ(KNkq) + (fu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}