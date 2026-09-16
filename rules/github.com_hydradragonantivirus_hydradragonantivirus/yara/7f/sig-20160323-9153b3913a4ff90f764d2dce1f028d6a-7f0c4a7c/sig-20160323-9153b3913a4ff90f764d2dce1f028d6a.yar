rule sig_20160323_9153b3913a4ff90f764d2dce1f028d6a {
  meta:
    description = "datamaliciousorder - file 20160323_9153b3913a4ff90f764d2dce1f028d6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7140f83f327bb5ebdec928f1a1f16ce0a2bce79b71be6957ab2824ea8683b5c8"

  strings:
    $s1  = "function Fg(iu){var _112crap = \"s\"; return \"\" + iu + \"\";};function VM(c1){var _112crap = \"s\"; return \"\" + c1 + \"\";};" ascii
    $s2  = " + V(sgN)](z());var ra = new this[R1(s)](),hY = ra[MqC + cTg + ER(Y) + Z1(zDu) + cw(txX)]();WScript[Sbq(i2) + F0(sgN)](z());var " ascii
    $s3  = "76ac\";var g = \"\\x74p:\\x2f\\x2f\",WqE = \"ht\";function j0(y1){var _112crap = \"s\"; return \"\" + y1 + \"\";};var E = \"TRTx" ascii
    $s4  = ";var pu = 0,QqL = 0;function G(){var ra = new this[zed(s)](),Xa = ra[s0(MqC) + cO(cTg) + Y + Etp(zDu) + lc(txX)]();WScript[r(i2)" ascii
    $s5  = "nction v(BU) {var PVP = (1, 2, 3, 4, 5, BU); return PVP;};pu = (U0) ? 14134 : 414234;N = WScript[l()](aRR(p) + s1(eS) + y2(BR0) " ascii
    $s6  = "Ob\";var A = MeB[\"char\"+\"\\x41\"+\"t\"](1),BYa = \"C\\x72e\";var Bj = false,NA = function xH() {return WScript[BYa + A + Wra(" ascii
    $s7  = " Y = \"\\x4dill\\x69\",cTg = \"C\";var MqC = \"getUT\";function zed(B){var _112crap = \"s\"; return \"\" + B + \"\";};function R" ascii
    $s8  = "unction aLu(){return pw(Kza) + ePg + i1(CPW) + UQm(c);};function zyB(vd, KrU){return vd - KrU;};function l(){return R(BYa) + eLV" ascii
    $s9  = "= dm) && (U0 == true)) ? true : false;};if (U0 && Z() && dm){function qk() {return NA[Q1(z0) + v1 + rF(xFL) + pG(Ibd) + oEv(vFr)" ascii
    $s10 = "< 4 ) {WScript[i2 + sF(sgN)](z() * 10)};BR = false;} catch(YH){BR = (JPE(D0) + hTW(pn), L(v2) + rq, w0(PG) + Vq(Y1), true);};}fu" ascii
    $s11 = "\\x65\",qn = \"\\x4aEh\";var OXF = \"y\",G0 = \"\\x69sK\\x6di\";var yzB = \"\\x77\\x56f\";function gnf(Kk){var _112crap = \"s\";" ascii
    $s12 = "zyB(ewq, hY);return zyB(pu, QqL);}var U0 = false,dm = false;for (var rT = 0; rT < z() * 1; rT++){if (G() != 0){U0 = true; QqL = " ascii
    $s13 = "2crap = \"s\"; return \"\" + JI + \"\";};function I(d){var _112crap = \"s\"; return \"\" + d + \"\";};function R(oJd){var _112cr" ascii
    $s14 = " return \"\" + JqT + \"\";};function JU0(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};function K0(zu){var _112crap = \"s" ascii
    $s15 = " = \"se\";function HrF(h){var _112crap = \"s\"; return \"\" + h + \"\";};function P0(zO){var _112crap = \"s\"; return \"\" + zO " ascii
    $s16 = "){var _112crap = \"s\"; return \"\" + xdB + \"\";};function JV(gH){var _112crap = \"s\"; return \"\" + gH + \"\";};function K1(l" ascii
    $s17 = "unction Sdz(e1){var _112crap = \"s\"; return \"\" + e1 + \"\";};var UC = \"CCewb\",lot = UC[\"char\"+\"\\x41\"+\"t\"](2);var ADW" ascii
    $s18 = "rap = \"s\"; return \"\" + l2 + \"\";};var blE = \"2\\x73\\x6fs\",IK = \"/l\";var UW = \".\\x72u\",x = \"to\\x724\\x33\";var zz " ascii
    $s19 = "= \"n\";var Lqg = \"o\\x70e\";function aRR(a){var _112crap = \"s\"; return \"\" + a + \"\";};function s1(fS){var _112crap = \"s" ascii
    $s20 = "var _112crap = \"s\"; return \"\" + ly + \"\";};var v0 = \"un\",Cor = \"\\x52\";function wq(qq){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}