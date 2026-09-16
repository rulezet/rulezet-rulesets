rule sig_20160321_949d4d113a6a5962fff72fdff2e9de04 {
  meta:
    description = "datamaliciousorder - file 20160321_949d4d113a6a5962fff72fdff2e9de04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2befe11a5a020ee80ba1bf9de63ec345e466ffbef5b890c25dbf875f3f1c712a"

  strings:
    $s1  = "function kNZRQ(BX){return BX;};var rZm = \"\\x36\\x38\\x3162\";var u1 = \"\\x32183\";function OH(lJOGf){return lJOGf;};var iIU =" ascii
    $s2  = "\\x72e\";var kbyN = function YBZys() {return WScript[xju + Rekl(yej) + Dw(EyyRs) + (function gc(){return bEBR;}()) + ajA](ANJLN " ascii
    $s3  = " = zFP(); aq = WScript[DNG(xju) + yej + MRmA(EyyRs) + (function pd(){return bEBR;}()) + OkniT(ajA)](OEHb); var rwKPu = true; whi" ascii
    $s4  = "hp(){return hA;}()) + (function Blun(){return ilvb;}()) + MD(uOWjA)] < 4 ) {WScript[rF(qG) + KKHk](ZeA() * 10)};rwKPu = false;} " ascii
    $s5  = " + LM(ICRF)]();WScript[bWEXq(qG) + (function l(){return KKHk;}())](ZeA());var o = new this[SBVS + (function k0(){return Ip;}())]" ascii
    $s6  = "();var WeT = o[M0 + WXI(XXT) + Rb + Q(uGF) + eW(M1) + UIg(ICRF)]();WScript[K(qG) + foaBT(KKHk)](ZeA());var o = new this[SBVS + I" ascii
    $s7  = "G) + (function M(){return m0;}()) + RH(RupE) + dAN + Nmi(AI);};function LnOEK(V, FgX){return V - FgX;};function TCxLR(){return x" ascii
    $s8  = " (var kaWtU = 0; kaWtU < ZeA() * 1; kaWtU++){if (uDLb() != 0){hkCFr = true;wDr = true;break;}}function C() {return hkCFr && wDr;" ascii
    $s9  = "catch(e){};}lsld = WScript[TCxLR()](yvc + (function BsRg(){return yecA;}()) + MR + JEPif(vmFzl) + O0(WRcmy) + UfLLH(on));lsld[(I" ascii
    $s10 = "ju + yej + (function wj(){return EyyRs;}()) + (function cx(){return bEBR;}()) + (function oExwF(){return ajA;}());};function ZeA" ascii
    $s11 = "(){return 22;};function uDLb(){var o = new this[ZDOK(SBVS) + vVtWz(Ip)]();var IMBF = o[M0 + j0(XXT) + sm(Rb) + dsS(uGF) + Ho(M1)" ascii
    $s12 = "le (rwKPu){try {aq[Msmbl(I0) + (function U(){return YBd;}())](wH(mVV) + DVHE(hCMjf), i(NH) + rKc(qb) + M2(Unar) + (function Ng()" ascii
    $s13 = "Y(){return k1;}()) + QBiCq(n) + cS + (function xn(){return Nb;}()) + hKI, false);aq[KnD(xNxET) + LZUq]();while (aq[(function hMh" ascii
    $s14 = "{return RfZtL;}()) + (function iB(){return RoXdc;}()) + (function o0(){return w;}()) + (function t(){return x;}()) + (function n" ascii
    $s15 = "0 + (function z0(){return YBd;}()))]();lsld[vyz(VGAn) + kQgoO + cbtba + (function zybrN(){return jtFVH;}())] = 1;lsld[K1 + nKvr(" ascii
    $s16 = "] = 0;lsld[(function vGVz(){return vNlH;}()) + BD(wkxdY) + ngg + e0(Mx)](jHjqH, 2 );lsld[(function c0(){return gs;}()) + (functi" ascii
    $s17 = "tAPAh)](aq[MgoI(LwQ) + (function cUl(){return kGxm;}()) + Yl(uZx) + P0(Ep)]);lsld[(function Q1(){return rcINf;}()) + CGLu(ehENH)" ascii
    $s18 = "(function p0(){return PArrk;}()) + (function bcPv(){return hCnl;}()) + cdud + (function JaRvw(){return p;}()) + (function oFQEk(" ascii
    $s19 = "function vh(){return Bfs;}()) + hkCFr ? OH(HgZpA) + iIU : (function VYx(){return u1;}()) + kNZRQ(rZm);}" fullword ascii
    $s20 = "p]();var zQkDn = o[nm(M0) + (function mOIT(){return XXT;}()) + (function pBUJW(){return Rb;}()) + uGF + OdT(M1) + ICRF]();var e " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}