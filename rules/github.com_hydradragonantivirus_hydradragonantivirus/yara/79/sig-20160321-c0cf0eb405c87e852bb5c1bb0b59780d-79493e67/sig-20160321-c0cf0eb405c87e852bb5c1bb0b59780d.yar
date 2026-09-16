rule sig_20160321_c0cf0eb405c87e852bb5c1bb0b59780d {
  meta:
    description = "datamaliciousorder - file 20160321_c0cf0eb405c87e852bb5c1bb0b59780d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6afc19689484c68d13c19a58ee05293d176f78192b64b49fa40a75f84bd8050b"

  strings:
    $s1  = "var x0 = \"\\x316\\x32\";var fTl = \"8\";var EXl = \"218\\x33\\x36\";function tVu(r0){return r0;};function fKIPN(t2){return t2;}" ascii
    $s2  = " \"te\";var LgEMT = \"Cr\\x65\\x61\";var aOllw = function zKRSv() {return WScript[LgEMT + (function NhYBe(){return ob;}()) + h(I" ascii
    $s3  = "on m(){return Waaax;}())]();while (uD[WuMVq(A) + eh(ouVi) + (function hCrF(){return tNuIh;}())] < 4 ) {WScript[T0(N) + SG](kET()" ascii
    $s4  = " (function UEoT(){return FqQq;}()) + AbmCy(EGTlZ) + bZ(lO) + oFRi(T1) + JCOby; ieZ = bRkAq(); uD = WScript[LgEMT + ob + (functio" ascii
    $s5  = ") + VVQd(CqYd) + (function GP(){return JuaX;}()) + vd]();WScript[HKVZ(N) + PgWsW(SG)](kET());var qt = new this[rKgxr + (function" ascii
    $s6  = "w this[W(rKgxr) + P(MH)]();var ra = qt[Ri + (function Bw(){return f;}()) + rQkHJ(CqYd) + Rv(JuaX) + vd]();WScript[(function lIas" ascii
    $s7  = " (function BUl(){return a0;}());};function Qk(ms, G){return ms - G;};function wv(){return (function T(){return LgEMT;}()) + (fun" ascii
    $s8  = ";lUEbQ[YC + (function bR(){return L;}())](uD[Hb + KEY + kJ + rmCPN + s0]);lUEbQ[ha(YeytW) + ukCZ(Pogd) + (function g0(){return K" ascii
    $s9  = "wU() {return wIJPL && cGj;};if (jwU()){fUmwu = aOllw[gf(J0) + (function RINU(){return Ph;}()) + khE(zaDtP) + x(jDauA) + lHI(CclB" ascii
    $s10 = " * 10)};X = false;} catch(e){};}lUEbQ = WScript[wv()](uL(rYso) + YOM + oeCkB + y0(Cmqdl));lUEbQ[(R0(UpLRM))]();lUEbQ[l + ve] = 1" ascii
    $s11 = ") + (function jPZTh(){return FKlAC;}()) + hsb + qfwo(vfbS) + UkQw(UACf)](Y(evhz) + (function E0(){return aacBb;}()) + yP(FGW)) +" ascii
    $s12 = "QdPO(){return JrY;}()) + Xl + (function hFi(){return Ic;}()) + wIJPL ? tVu(zLoXi) + (function WKM(){return HPy;}()) + ig + LjlB " ascii
    $s13 = "IJPL = false;var cGj = false;for (var yT = 0; yT < kET() * 1; yT++){if (FCPgL() != 0){wIJPL = true;cGj = true;break;}}function j" ascii
    $s14 = "(){return N;}()) + hxIF(SG)](kET());var qt = new this[mz(rKgxr) + (function B0(){return MH;}())]();var uQr = qt[f0(Ri) + XSkxv(f" ascii
    $s15 = "Jq), Chyuv + (function neelm(){return KwUWC;}()) + soNlr(MCTmK) + ro(Gm) + (function JZji(){return SXDeU;}()) + RHh + TwJ + bKzS" ascii
    $s16 = "ction R(){return ob;}()) + ICVA + (function i(){return nQj;}()) + RXxJ;};function kET(){return 22;};function FCPgL(){var qt = ne" ascii
    $s17 = " (function vk(){return nQj;}()) + B(RXxJ)](qgQsY(tFJ) + (function ml(){return K0;}()) + S(qT) + bfL(Oo));}();function LgsoY(Fwu)" ascii
    $s18 = "(qswIs) + (function Q0(){return v;}()) + (function wcEFo(){return bylin;}()), false);uD[(function W0(){return pDy;}()) + (functi" ascii
    $s19 = " KUEq(){return MH;}())]();var AkHO = qt[(function Uq(){return Ri;}()) + Fb(f) + yTLP(CqYd) + (function XR(){return JuaX;}()) + (" ascii
    $s20 = "{aOllw[(function HYVs(){return fJeSG;}())](Fwu, 0, 0);};function bRkAq(){return ZLgZX + mzd(PZLvt) + WBDb(sH) + a + yFFSd(XiF) +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}