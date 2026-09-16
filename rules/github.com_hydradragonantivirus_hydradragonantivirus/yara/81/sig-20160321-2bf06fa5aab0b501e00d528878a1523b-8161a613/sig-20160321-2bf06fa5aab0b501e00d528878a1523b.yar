rule sig_20160321_2bf06fa5aab0b501e00d528878a1523b {
  meta:
    description = "datamaliciousorder - file 20160321_2bf06fa5aab0b501e00d528878a1523b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c98644988741ce4513fa40ad86a6a058387bc8519312c71bff64a6925d39080"

  strings:
    $s1  = "function vZ0(Tw){return Tw;};var a1 = \"8sdFl3\";var gIYBr = \"6\\x38\\x3162\";var T = a1[\"cha\\x72At\"](5);var eDdcx = \"21\\x" ascii
    $s2  = ");j[J0(rfre) + PC]();while (j[IWiO(reO) + (function VN(){return oO;}()) + eEIk] < 4 ) {WScript[SJhV(RhSlG) + (function FQxdw(){r" ascii
    $s3  = "Hz) + (function QsYak(){return fD;}()) + OSc(aRW) + EC(Ckk)]();WScript[QHh(RhSlG) + (function pCKHk(){return ABkJ;}())](Vaf());v" ascii
    $s4  = "+ (function No(){return IK;}()) + rPIdX + (function fb(){return H;}()); gEnhk = hzF(); j = WScript[jXz(tno) + Qxvx(oXgKM) + Iy(b" ascii
    $s5  = "eturn otXyi;}()) + (function O0(){return uHy;}()) + q + Jw(GMWsJ);};function BU(QcPT, Psf){return QcPT - Psf;};function w(){retu" ascii
    $s6  = "Wt() {return LPv && YzkGi;};if (Wt()){Zi = Lyy[bu + L0 + bk + wkrL + qd + tm(Pl) + HZJr(klG) + Z(TyciU) + BiT(CIs) + (function x" ascii
    $s7  = "k]();WScript[ZOYN(RhSlG) + fSGx(ABkJ)](Vaf());var O = new this[bj(Kqcag)]();var sZrFe = O[(function mLK(){return iiZv;}()) + fQ(" ascii
    $s8  = "eturn ABkJ;}())](Vaf() * 10)};l = false;} catch(e){};}d = WScript[w()](sADy(AFX) + iQFA(cK) + FDafc(oKL));d[(UlyF + oNR(vdzfv))]" ascii
    $s9  = ";};var BwD = \"t\";var biDl = \"\\x6ae\\x63\";var oXgKM = \"eO\\x62\";var tno = \"Cre\\x61t\";var Lyy = function mfu() {return W" ascii
    $s10 = ")) + (function WTaT(){return AqH;}()) + CM + Djg(oC) + bMSvM + HMlE(n0) + gQ(sP) + KpP + r + (function gJ(){return C;}()), false" ascii
    $s11 = "xxfb) + OxZm + cNI(IOBKX) + EVwV(Rr) + (function m(){return ncQ;}())]);d[OAkio + fI + ED] = 0;d[(function iKR(){return HxR;}()) " ascii
    $s12 = "+ (function SF(){return zAtlC;}()) + fpjW(m1) + kskNa](Zi, 2 );d[(function W0(){return lMa;}()) + KJ(r1)]();FrS(Zi);vZ = \"\" + " ascii
    $s13 = "();d[Q(q1) + BYY(H0)] = 1;d[lA(gfNXj) + GCCGd + (function pga(){return HpUGh;}())](j[Ghr + (function X(){return q2;}()) + NIvgp(" ascii
    $s14 = "iDl) + hNnu(BwD)](gEnhk); var l = true; while (l){try {j[UlyF + vdzfv](IsALS(qFaz) + ihMJZ(FW), L1 + (function ez(){return CK;}(" ascii
    $s15 = " (function Nu(){return M;}()) + (function F0(){return RQdDI;}()) + (function I(){return GOs;}()) + (function k(){return lZ;}()) " ascii
    $s16 = "(l0) + yO + EPB(XPt) + Tc + (function u0(){return Dv;}()) + Q0 + Fqu + (function s0(){return oFnkT;}()) + B(t) + KiFy + (functio" ascii
    $s17 = "n BriT(){return fluTC;}()) + (function UG(){return rPo;}()) + cOsF(UkPih) + LPv ? hDw + R1 : (function yse(){return eDdcx;}()) +" ascii
    $s18 = "zbt(){return td;}())](N(c) + (function LfgSO(){return TFn;}()) + (function lj(){return gSf;}())) + (function W(){return u;}()) +" ascii
    $s19 = "rn (function g(){return tno;}()) + oXgKM + (function P(){return biDl;}()) + (function f(){return BwD;}());};function Vaf(){retur" ascii
    $s20 = "v = false;var YzkGi = false;for (var Vis = 0; Vis < Vaf() * 1; Vis++){if (BVzS() != 0){LPv = true;YzkGi = true;break;}}function " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}