rule sig_20160323_f4b01f6be5de26b48792cbd64d3c66fa {
  meta:
    description = "datamaliciousorder - file 20160323_f4b01f6be5de26b48792cbd64d3c66fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9b47f76541b4e1db816006da62db6dd236fcc0a4bad4428ad2e3e1163b9523"

  strings:
    $s1  = ");};}function W(z) {var Ylq = (1, 2, 3, 4, 5, z); return Ylq;};Eij = (b) ? 14134 : 414234;EB = WScript[XzI()](MJ(JaL) + RpK + F1" ascii
    $s2  = "Q(B) + g0(A0) + IF + rh(qdL) + g1(G)]();WScript[xU(Uz) + Vy(To)](oX());var jD = new this[tZ(EVj) + Qi(Cwa)](),sY = jD[oRv(B) + A" ascii
    $s3  = "() {return WScript[Qsn(jsV) + Ty(Mmi) + Zbp + v + lV + oEr(NMe) + n0(Ti)](F(qwq) + iXQ(cW) + RpW + fYX(zs));}();function qOs(is)" ascii
    $s4  = "function hgV(UAo){var _112crap = \"s\"; return \"\" + UAo + \"\";};function okl(J4){var _112crap = \"s\"; return \"\" + J4 + \"" ascii
    $s5  = " G = \"nds\",qdL = \"i\\x73eco\";var IF = \"ill\",A0 = \"\\x54C\\x4d\";var B = \"getU\";function t0(GDN){var _112crap = \"s\"; r" ascii
    $s6  = "{A[GjH(ivC) + g(h0)](is, 0, 0);};function TPo(){return r0 + xu + GDh(bVp) + opU + kqa(pZ);};function nY(f0, KT){return f0 - KT;}" ascii
    $s7  = " (b && IjA() && qWM){function nmZ() {return A[Lxu(u1) + y(q1) + qX + Uq(aRd) + deK + BYv(LDo) + B0 + X(wtd) + PRx(B1) + M0(nj) +" ascii
    $s8  = "rue; tJk = \"07t9gasdf76ags\" + 123313 * Eij + tJk; break;}}function IjA() {return ((b == qWM) && (b == true)) ? true : false;};" ascii
    $s9  = "] < 4 ) {WScript[VGg(Uz) + q0(To)](oX() * 10)};r = false;} catch(z0){r = (CwS(Pm) + KUt(LmW), Y(Lwo) + J1(ew), y0 + eR(SY), true" ascii
    $s10 = "L = jD[CAR(B) + lYI(A0) + AS(IF) + qdL + C(G)]();WScript[O2(Uz) + fBU(To)](oX());var jD = new this[k(EVj) + zt(Cwa)](),phO = jD[" ascii
    $s11 = "turn \"\" + c + \"\";};function KUt(i1){var _112crap = \"s\"; return \"\" + i1 + \"\";};var LmW = \"\\x66a\",Pm = \"a\\x73d\";va" ascii
    $s12 = "};function q0(u){var _112crap = \"s\"; return \"\" + u + \"\";};var Op = \"wyA09SU2d\",To = \"leep\";var Uz = Op[\"cha\"+\"\\x72" ascii
    $s13 = ";};function j(aL){var _112crap = \"s\"; return \"\" + aL + \"\";};function Pe(Q1){var _112crap = \"s\"; return \"\" + Q1 + \"\";" ascii
    $s14 = "Pg + \"\";};function K0(p){var _112crap = \"s\"; return \"\" + p + \"\";};function U(rFY){var _112crap = \"s\"; return \"\" + rF" ascii
    $s15 = "function J1(h1){var _112crap = \"s\"; return \"\" + h1 + \"\";};var ew = \"\\x73df\",Lwo = \"fadfa\";function CwS(c){var _112cra" ascii
    $s16 = "{var _112crap = \"s\"; return \"\" + f1 + \"\";};function oEr(AC){var _112crap = \"s\"; return \"\" + AC + \"\";};function n0(Ax" ascii
    $s17 = "112crap = \"s\"; return \"\" + W2 + \"\";};var BCP = \"nFKLOsu\",Hnx = \"e\\x6ed\";var AdF = BCP[\"cha\"+\"\\x72\"+\"At\"](5);fu" ascii
    $s18 = " = \"s\"; return \"\" + Ta + \"\";};function M0(Kcb){var _112crap = \"s\"; return \"\" + Kcb + \"\";};function M1(ld){var _112cr" ascii
    $s19 = "\"; return \"\" + jM + \"\";};var n1 = \"o\\x64y\",v1 = \"onseB\";var c0 = \"\\x52esp\";function WqB(LaD){var _112crap = \"s\"; " ascii
    $s20 = "_112crap = \"s\"; return \"\" + i0 + \"\";};function aTN(Mu0){var _112crap = \"s\"; return \"\" + Mu0 + \"\";};function LA(fkS){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}