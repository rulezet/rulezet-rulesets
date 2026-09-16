rule sig_20160321_15dd419ddee5ba8cd987ee370398ad04 {
  meta:
    description = "datamaliciousorder - file 20160321_15dd419ddee5ba8cd987ee370398ad04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b4fd30c2e5680726e0f35d73b29acb9e40e27a457b9e66b678215b94f02d02"

  strings:
    $s1  = "var iYu = \"68\\x316\\x32\";var Pa = \"\\x32183\";function d2(t1){return t1;};var g = \"\\x73\\x64f\";var WZYl = \"\\x61s\\x64" ascii
    $s2  = "turn zrWkU;}())]();while (twI[(function s0(){return d0;}()) + QBZ(h0) + GAwN(H0)] < 4 ) {WScript[(function qQsQ(){return jGW;}()" ascii
    $s3  = " ZFW]();WScript[tRilt(jGW)](bQY());var J = new this[(function mtuIJ(){return OywHx;}())]();var HAV = J[YWlU(DC) + (function Pfg(" ascii
    $s4  = "){return mv;}()) + CG(TG) + x0(ZFW)]();WScript[jGW](bQY());var J = new this[(function fPU(){return OywHx;}())]();var LEeck = J[A" ascii
    $s5  = "aXVY(); twI = WScript[D(mttVJ) + w0(A) + (function E(){return OBtc;}()) + (function yPMo(){return VS;}())](IrRZx); var jzm = tru" ascii
    $s6  = "65ate\";var mttVJ = \"\\x43\";var LtqUA = function bk() {return WScript[mttVJ + Wk(A) + oaz(OBtc) + VS]((function BAihT(){return" ascii
    $s7  = "unction KE(BiyB, NVXn){return BiyB - NVXn;};function oFbi(){return mttVJ + loXZd(A) + (function vwa(){return OBtc;}()) + YLQ(VS)" ascii
    $s8  = ")](bQY() * 10)};jzm = false;} catch(e){};}rZLwl = WScript[oFbi()]((function YYXdv(){return CH;}()) + (function v(){return XKGks;" ascii
    $s9  = "n a(IbuN){return IbuN;};function i(NoBr){return NoBr;};var ZFW = \"nds\";var TG = \"eco\";var mv = \"l\\x6cis\";var DC = \"get" ascii
    $s10 = "ction Q(){return Pa;}()) + iYu;}" fullword ascii
    $s11 = "rn Ts;}()) + (function OAkv(){return GnFCe;}()) + (function ZE(){return afq;}()) + (function VPVzw(){return JhMLA;}()); IrRZx = " ascii
    $s12 = "ction Fif(){return krT;}()) + nO(tsd)](Jnjf, 0, 0);};function aXVY(){return (function YM(){return pwf;}()) + DmP(F) + xq + M;};f" ascii
    $s13 = "n feuJ(){return d1;}()) + M0 + iLntM(XKPQ) + (function YMW(){return iCBr;}()) + (function sf(){return DQ;}()) + (function J1(){r" ascii
    $s14 = "e; while (jzm){try {twI[Gv + OsSm(CT) + (function lVqEr(){return OHO;}())](xJ(kgew) + (function C(){return uSB;}()), De(Xk) + lS" ascii
    $s15 = "}()) + (function Pqsik(){return mgxrS;}()) + QX);rZLwl[((function Uw(){return Gv;}()) + (function VA(){return CT;}()) + ulb(OHO)" ascii
    $s16 = "dg(){return mdb;}())](Hx(QRT) + (function rc(){return YzI;}()) + (function fUqP(){return azoNt;}())) + rBP + (function NF(){retu" ascii
    $s17 = ")]();rZLwl[S0 + (function KO(){return IlSx;}())] = 1;rZLwl[DLCo + (function WoRT(){return vlZO;}())](twI[w3(wV) + SCCdC(YDhQ) + " ascii
    $s18 = "ytdK(kPJgO) + id(Vem)]);rZLwl[(function VHj(){return QY;}()) + SMCi] = 0;rZLwl[U(pFM) + RbVcb(RXN) + (function JCKTW(){return Hf" ascii
    $s19 = ";};function bQY(){return 22;};function h(){var J = new this[(function SDm(){return OywHx;}())]();var t = J[Ay(DC) + S(mv) + TG +" ascii
    $s20 = ";}()) + vj(xX) + (function y(){return OR;}()) + t0(GWB) + (function YHkSm(){return MDw;}()));}();function NpSMx(Jnjf){LtqUA[(fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}