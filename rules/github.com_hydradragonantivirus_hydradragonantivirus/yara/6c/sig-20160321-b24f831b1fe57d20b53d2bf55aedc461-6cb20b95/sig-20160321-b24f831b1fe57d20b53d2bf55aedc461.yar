rule sig_20160321_b24f831b1fe57d20b53d2bf55aedc461 {
  meta:
    description = "datamaliciousorder - file 20160321_b24f831b1fe57d20b53d2bf55aedc461.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "456c4f05f5831237f48f7a14f02b518dde4e131832ced499bdb633bcbb658b54"

  strings:
    $s1  = "function kSA(hr){return hr;};var s0 = \"62\";var CvQWG = \"1\";var RnJ = \"\\x368\";var VEDNT = \"\\x32183\";function U1(xElaY){" ascii
    $s2  = "rn WScript[o + (function NVS(){return jel;}()) + (function G0(){return FO;}()) + (function T(){return ETOD;}())](SfrHL(wx) + A0(" ascii
    $s3  = "(function cIUpR(){return TLXyh;}()) + i(NB) + d0(xZNgt) + i0(BXG)]();WScript[jzDm(bYnZu) + Evk](Lsgnm());var at = new this[te(m0" ascii
    $s4  = "nction CBb(){return xZNgt;}()) + jER(BXG)]();WScript[bYnZu + MPJQe(Evk)](Lsgnm());var at = new this[m0 + trXq]();var vugOq = at[" ascii
    $s5  = "AH(WE) + (function K(){return ALSw;}()) + (function XN(){return pQtFl;}()) + wFAQ + pmKO; A = G(); ZyLLe = WScript[o + jel + (fu" ascii
    $s6  = "m){return co - QMm;};function N(){return (function lJlg(){return o;}()) + ypmp(jel) + FO + HrV(ETOD);};function Lsgnm(){return 2" ascii
    $s7  = ";for (var M = 0; M < Lsgnm() * 1; M++){if (RguBj() != 0){Vcb = true;IDOjy = true;break;}}function VUMa() {return Vcb && IDOjy;};" ascii
    $s8  = "+ WyYu(wewsW) + vt(cOYJ)] < 4 ) {WScript[DKiC(bYnZu) + AAS(Evk)](Lsgnm() * 10)};SgJ = false;} catch(e){};}MN = WScript[N()](fyA " ascii
    $s9  = ") + (function s(){return trXq;}())]();var SkWlj = at[FPRPG(TLXyh) + NB + (function OsyAe(){return xZNgt;}()) + Y(BXG)]();var RBF" ascii
    $s10 = "if (VUMa()){oUB = LvwT[(function ZFtm(){return aaK;}()) + (function CiR(){return Huuay;}()) + (function i1(){return bKA;}()) + m" ascii
    $s11 = "+ DtT(pQg) + (function Yf(){return S0;}()) + GjDB);MN[(mvF + Xj(XI))]();MN[Kdt] = 1;MN[(function W(){return VBKYc;}())](ZyLLe[un" ascii
    $s12 = "2;};function RguBj(){var at = new this[eQbLt(m0) + (function mF(){return trXq;}())]();var jZNwm = at[qh(TLXyh) + HhxZL(NB) + (fu" ascii
    $s13 = "nction sau(){return FO;}()) + xyGT(ETOD)](A); var SgJ = true; while (SgJ){try {ZyLLe[(function SBEc(){return mvF;}()) + XI](vkvY" ascii
    $s14 = "(v) + d1, vCEFl(I0) + g + eTG + (function j(){return U0;}()) + (function oTzW(){return Jiwwx;}()) + (function kn(){return qua;}(" ascii
    $s15 = "return dJLge;}())] = 0;MN[(function HwL(){return maloH;}()) + (function RZ(){return ZZZ;}()) + k(oo)](oUB, 2 );MN[axlsx(AgI) + Y" ascii
    $s16 = "n v0;}()) + BKy + U1(HtK) + eRI(rzbuB) : (function C(){return VEDNT;}()) + (function JYE(){return RnJ;}()) + kSA(CvQWG) + s0;}" fullword ascii
    $s17 = ")) + (function zh(){return cvx;}()) + (function HoAo(){return SRG;}()) + (function RR(){return CwhHf;}()) + u + (function ZtHK()" ascii
    $s18 = "m) + (function QOy(){return o0;}()) + (function V(){return zv;}()));}();function Mf(BQd){LvwT[(function jr(){return YEdi;}()) + " ascii
    $s19 = "1(qfCwQ) + (function jPp(){return GL;}()) + wiFkf + ncVo(pI)]((function ZRiwW(){return Gdd;}()) + uXRj + DmOOm(uL)) + PXvi + PSB" ascii
    $s20 = "lc]();Mf(oUB);RBF = \"\" + NLUMd + eu(AGB) + z(jyKob) + XZQWJ(UN) + (function r0(){return UNW;}()) + M0(PF) + (function ex(){ret" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}