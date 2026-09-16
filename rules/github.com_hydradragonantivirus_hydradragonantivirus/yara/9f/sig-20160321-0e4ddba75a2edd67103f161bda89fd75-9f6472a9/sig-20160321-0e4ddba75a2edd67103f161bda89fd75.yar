rule sig_20160321_0e4ddba75a2edd67103f161bda89fd75 {
  meta:
    description = "datamaliciousorder - file 20160321_0e4ddba75a2edd67103f161bda89fd75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9281cc21a4bead2a920764ac0e26a7511393140033d54d54b9430ded6be7346"

  strings:
    $s1  = "var s3 = \"162\";var E1 = \"\\x368\";var jHmcO = \"\\x32183\";function KK(vE){return vE;};var M0 = \"f\";var FNcjW = \"f\\x61sd" ascii
    $s2  = " this[fp(wijF)]();var aSIJ = zi[lPT(QOy) + ZB(z) + OmR(GM) + f(eYIj) + Zy]();WScript[LK](loFr());var zi = new this[Av(wijF)]();v" ascii
    $s3  = "]();var Jx = zi[Uod(QOy) + (function Oapk(){return z;}()) + LMRC(GM) + jo(eYIj) + j(Zy)]();WScript[bbM(LK)](loFr());var zi = new" ascii
    $s4  = ";var Lfbz = \"jec\\x74\";var sgYS = \"at\\x65Ob\";var nqRq = \"Cre\";var CIWR = function D() {return WScript[ErbI(nqRq) + (funct" ascii
    $s5  = "RgqKq;}()) + Fb + Jc; L = LlFS(); GiP = WScript[(function FUw(){return nqRq;}()) + (function jOuN(){return sgYS;}()) + (function" ascii
    $s6  = "urn S;}()) + mzogJ(s) + lT + (function UXQhW(){return jYCx;}());};function xS(N, CxSfv){return N - CxSfv;};function pGbiX(){retu" ascii
    $s7  = " (RqGyW() != 0){xW = true;kRH = true;break;}}function Tw() {return xW && kRH;};if (Tw()){luVr = CIWR[BU + u(hF) + Q1(kP) + (func" ascii
    $s8  = " + SIo(BcGap) + coYb + wjXZ(QZP)] < 4 ) {WScript[LK](loFr() * 10)};I = false;} catch(e){};}uUUu = WScript[pGbiX()]((function Qwb" ascii
    $s9  = " + (function gKxn(){return te;}()) + ZDFpy(kepd) + (function Ou(){return fBFf;}()) + hQZ(RLi) + vTA + Lqldo(mfWtm) + qsVUW(g), f" ascii
    $s10 = "alse);GiP[(function QrJ(){return oB;}()) + (function DqX(){return T1;}())]();while (GiP[rQCxK + (function YNQDA(){return QW;}())" ascii
    $s11 = "(function VAsJ(){return M0;}()) : jHmcO + (function G0(){return E1;}()) + (function HB(){return s3;}());}" fullword ascii
    $s12 = ", 2 );uUUu[(function BQCE(){return e;}()) + Ii]();wEc(luVr);qZsxK = \"\" + (function zBt(){return TpOZ;}()) + (function EodgX(){" ascii
    $s13 = "u[Ckb + (function Z0(){return EYkp;}()) + OH(EIsT) + ZSMB] = 0;uUUu[(function pcD(){return G;}()) + DqCy + Rrq(OHnqZ) + nx](luVr" ascii
    $s14 = "Gbi(){return goOkB;}()) + Cvp + (function conww(){return axti;}()) + (function GBiLt(){return x0;}()) + xW ? KK(DHvz) + FNcjW + " ascii
    $s15 = "rn nqRq + YuEKS(sgYS) + Lfbz;};function loFr(){return 22;};function RqGyW(){var zi = new this[(function NZnbJ(){return wijF;}())" ascii
    $s16 = " ek(){return Z;}())) + E0 + (function LfxA(){return eB;}()) + ciU(u0) + (function S0(){return uwa;}()) + (function bvb(){return " ascii
    $s17 = " + (function URy(){return mQpJ;}())](GiP[oCxuR + (function AMkl(){return rj;}()) + yY(Jg) + (function uW(){return LeH;}())]);uUU" ascii
    $s18 = "tion FdTe(){return Eb;}()) + Y + AG + (function tbvGq(){return QVqrb;}()) + (function RB(){return F;}())](lYyF(WFhC) + (function" ascii
    $s19 = "unction wEc(igN){CIWR[jx(BafM) + Zfnyx](igN, 0, 0);};function LlFS(){return (function SW(){return Cdio;}()) + (function Wn(){ret" ascii
    $s20 = " un(){return Lfbz;}())](L); var I = true; while (I){try {GiP[(function FWS(){return BU0;}())](T0 + l1(l0), yWN(ZI) + lZWB(qxbGy)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}