rule sig_20160323_2c4083fa65bce0e4aac1045330b54574 {
  meta:
    description = "datamaliciousorder - file 20160323_2c4083fa65bce0e4aac1045330b54574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617aa36424f8c0c21be1bfba14efd7ef716a52c4e640beb06f102ba0f3f9eb39"

  strings:
    $s1  = "function Z0(GS){var _112crap = \"s\"; return \"\" + GS + \"\";};var hMn = \"cl\\x6fse\";function g4(SJ){var _112crap = \"s\"; re" ascii
    $s2  = "* c + b; break;}}function h() {return ((KeF == bh) && (KeF == true)) ? true : false;};if (KeF && h() && bh){function ljh() {retu" ascii
    $s3  = ") + re(h2) + HaJ(WV);}; R = U(); YmD = WScript[An(XuE) + m(uwP) + Jv(jpZ) + o + UHR(wE)](R); var M = true; while (M){try {YmD[I " ascii
    $s4  = "+ fkt + hqN(CN), true);};}function l(ft) {var g = (1, 2, 3, 4, 5, ft); return g;};c = (KeF) ? 14134 : 414234;P = WScript[Q()](j2" ascii
    $s5  = ";var cXr = false,jdl = function tZ() {return WScript[XuE + a(uwP) + U0(jpZ) + rc(o) + oG(wE)](TUt(g2) + hE(csP) + Zd(gWI) + kwq(" ascii
    $s6  = "cMO) + w + pem(QHo) + f]();WScript[D1 + qE(zvo)](Yi());var zfF = new this[CO(i) + LyA](),N = zfF[eVj + y + G0(cMO) + JjG(w) + sZ" ascii
    $s7  = "(QHo) + RbN(f)]();WScript[bsz(D1) + sbQ(zvo)](Yi());var zfF = new this[ebs(i) + LyA](),fL = zfF[b0(eVj) + YM(y) + cMO + w + y0(Q" ascii
    $s8  = " + R1(J)] < 4 ) {WScript[O0(D1) + zvo](Yi() * 10)};M = false;} catch(zW){M = (LBT + llP(sUo), c1(WQ) + M1(ie) + T(aZB), Q2(sml) " ascii
    $s9  = "61\",JI = \"om\\x2fio\";var IAR = \"l\\x74\\x2ec\",wEv = \"nsu\";var rJJ = \"l\\x2dco\",i1 = \"\\x2f/\\x76\";var hUi = \"ht\\x74" ascii
    $s10 = "tion Ky(V){var _112crap = \"s\"; return \"\" + V + \"\";};function k0(KZ){var _112crap = \"s\"; return \"\" + KZ + \"\";};var TS" ascii
    $s11 = "p4 = \"P%/\",MNG = \"\\x25TE\\x4d\";function t0(TaP){var _112crap = \"s\"; return \"\" + TaP + \"\";};function pDx(WB){var _112c" ascii
    $s12 = "\";};function IyH(tN){var _112crap = \"s\"; return \"\" + tN + \"\";};function S0(jZ){var _112crap = \"s\"; return \"\" + jZ + " ascii
    $s13 = "urn \"\" + Qln + \"\";};var J = \"sta\\x74e\",yD = \"ady\";var p5 = \"re\";function v0(I1){var _112crap = \"s\"; return \"\" + I" ascii
    $s14 = " q + \"\";};function Dg(r){var _112crap = \"s\"; return \"\" + r + \"\";};function o0(xPc){var _112crap = \"s\"; return \"\" + x" ascii
    $s15 = " + zdo + \"\";};function joC(Rx){var _112crap = \"s\"; return \"\" + Rx + \"\";};function tLI(nQx){var _112crap = \"s\"; return " ascii
    $s16 = " n < Yi() * 1; n++){if (jno() != 0){KeF = true; b = \"07t9gasdf76ags\" + 123313 * c + b; bh = true; b = \"07t9gasdf76ags\" + 123" ascii
    $s17 = "r){function Yi(){return 22;};var c = 0,b = 0;function jno(){var zfF = new this[Di(i) + YCs(LyA)](),E = zfF[p2(eVj) + j0(y) + zx(" ascii
    $s18 = "O(WG){var _112crap = \"s\"; return \"\" + WG + \"\";};var E4 = \"tion\",WR = \"po\\x73\\x69\";function M2(zdo){var _112crap = \"" ascii
    $s19 = " \"\";};function I3(E3){var _112crap = \"s\"; return \"\" + E3 + \"\";};var u = \"Bjy\",v1 = \"\\x6fdy\";var Wnk = u[\"\"+\"\\x6" ascii
    $s20 = "+ DS(TSL)](I0(h3), hUi + XW(i1) + lLO(rJJ) + IyH(wEv) + S0(IAR) + wWn(JI) + Ah(n2), false);YmD[v0(FkU)]();while (YmD[WX(p5) + yD" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}