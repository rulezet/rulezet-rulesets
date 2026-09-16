rule sig_20160323_6aeff67c6d0af9f02860d881ae832574 {
  meta:
    description = "datamaliciousorder - file 20160323_6aeff67c6d0af9f02860d881ae832574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13a9fbe959142db9e3825fef92303d7ea247cf59e57cfe92badb8351181601a8"

  strings:
    $s1  = "\\x72\\x65\\x61t\";var Fx = \"C\",BeV = false;var mg = function qPo() {return WScript[Fx + krC(l0) + ugT(MNL) + V0(h) + bD(B)](K" ascii
    $s2  = "(mS) + oKP(h1) + ov(oN);}; HXA = ZV(); l = WScript[VBg(Fx) + l0 + Y(MNL) + h + g(B)](HXA); var U = true; while (U){try {l[GPV(ye" ascii
    $s3  = ";function V(w, YZ){return w - YZ;};function JPS(){return qa(Fx) + pz(l0) + Vo(MNL) + T(h) + B;};/*@cc_on  @if (@_win32 || @_win6" ascii
    $s4  = "313 * n + P; break;}}function mR() {return ((ayF == z) && (ayF == true)) ? true : false;};if (ayF && mR() && z){function ce() {r" ascii
    $s5  = "+ iE(HD)] < 4 ) {WScript[VXE(NN) + xRM(U1) + wA(Xh)](GNQ() * 10)};U = false;} catch(UW){U = (y0(hQ) + j1, Shl(Yq) + Q2 + YK(F0)," ascii
    $s6  = "function IS(n0){var _112crap = \"s\"; return \"\" + n0 + \"\";};function Z(DZ){var _112crap = \"s\"; return \"\" + DZ + \"\";};v" ascii
    $s7  = "rn \"\" + o0 + \"\";};function Uh(Bu){var _112crap = \"s\"; return \"\" + Bu + \"\";};var s2 = \"Fil\\x65\",d2 = \"To\";var nZ =" ascii
    $s8  = ";function VTC(rQ){var _112crap = \"s\"; return \"\" + rQ + \"\";};function gH(Ve){var _112crap = \"s\"; return \"\" + Ve + \"\";" ascii
    $s9  = "\"C\\x72e\";function Q0(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};function oKP(U3){var _112crap = \"s\"; return \"\" +" ascii
    $s10 = ";};function LzZ(N0){var _112crap = \"s\"; return \"\" + N0 + \"\";};function tv(o){var _112crap = \"s\"; return \"\" + o + \"\";" ascii
    $s11 = "{var _112crap = \"s\"; return \"\" + sVU + \"\";};function z1(Dm){var _112crap = \"s\"; return \"\" + Dm + \"\";};function Nh(j2" ascii
    $s12 = " \"e\\x4f\\x62\";var E = \"Cr\\x65a\\x74\";function V1(qOs){var _112crap = \"s\"; return \"\" + qOs + \"\";};var mJs = \"\\x54TP" ascii
    $s13 = "on aAs(NvD){var _112crap = \"s\"; return \"\" + NvD + \"\";};function a(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};func" ascii
    $s14 = "ion q0(UM){var _112crap = \"s\"; return \"\" + UM + \"\";};function zuy(CR){var _112crap = \"s\"; return \"\" + CR + \"\";};var " ascii
    $s15 = "crap = \"s\"; return \"\" + c + \"\";};function X(XUk){var _112crap = \"s\"; return \"\" + XUk + \"\";};function nMd(R1){var _11" ascii
    $s16 = "c\\x6f\";var nm = \"\\x2f\\x76l-\",u2 = \"\\x74p:/\";var Ssu = \"ht\",c0 = \"G\\x45\\x54\";function GPV(IjD){var _112crap = \"s" ascii
    $s17 = "\" + jDp + \"\";};function SXT(se){var _112crap = \"s\"; return \"\" + se + \"\";};function g1(T1){var _112crap = \"s\"; return " ascii
    $s18 = "tion yUQ(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};function i(M1){var _112crap = \"s\"; return \"\" + M1 + \"\";};var " ascii
    $s19 = "nction ov(cl){var _112crap = \"s\"; return \"\" + cl + \"\";};var oN = \"\\x65\",h1 = \"M\\x41\\x2eex\";var mS = \"gO\\x57eT\",j" ascii
    $s20 = " WYy(CuR) + YfN(f2), true);};}function aLb(KE) {var jR = (1, 2, 3, 4, 5, KE); return jR;};n = (ayF) ? 14134 : 414234;k0 = WScrip" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}