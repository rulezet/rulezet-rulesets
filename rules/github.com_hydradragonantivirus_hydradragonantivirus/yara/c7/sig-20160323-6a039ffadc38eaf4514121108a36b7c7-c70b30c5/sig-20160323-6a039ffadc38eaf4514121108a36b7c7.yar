rule sig_20160323_6a039ffadc38eaf4514121108a36b7c7 {
  meta:
    description = "datamaliciousorder - file 20160323_6a039ffadc38eaf4514121108a36b7c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56f5b3c0fd9b7f8401345a94723fe810ff51895639a544a96399100108173aa2"

  strings:
    $s1  = "function ADr(JZ){var _112crap = \"s\"; return \"\" + JZ + \"\";};var DZ = \"crEg1c\",elE = \"e\";var x1 = \"los\",Wc = DZ[\"ch\"" ascii
    $s2  = "\"\" + gD + \"\";};var p = \"ect\",be = \"eObj\";var O = \"Cre\\x61\\x74\",zjY = false;var eT = function i() {return WScript[O +" ascii
    $s3  = "());var lt = new this[Cb(Pvj) + nou + lE(ok)](),o = lt[rBr + SGY(fj) + tJ(u) + gyT(Bff) + zdV(izu) + q0(l1) + aUF(bi)]();WScript" ascii
    $s4  = "ar Sh = \"\\x2f\\x2f\\x74ir\",at = \"h\\x74\\x74p:\";function n(W0){var _112crap = \"s\"; return \"\" + W0 + \"\";};var H0 = \"G" ascii
    $s5  = "this[fb(Pvj) + nou + ok](),e = lt[ND(rBr) + h0(fj) + sPJ(u) + X0(Bff) + D(izu) + pcN(l1) + iFP(bi)]();WScript[h1(T) + qc(RE)](ln" ascii
    $s6  = "Iwr(v0) + x + R1;}; d = NN(); rIa = WScript[AtM(O) + GqI(be) + wjr(p)](d); var CU = true; while (CU){try {rIa[Ee(AcI) + u1(y)](n" ascii
    $s7  = "R) + pQ(l0) + o0(tOB) + Bac(slF);};function G(QOE, f){return QOE - f;};function tF(){return l(O) + h(be) + rqK(p);};/*@cc_on  @i" ascii
    $s8  = "\" + 123313 * MIS + GT; break;}}function A() {return ((xpg == X) && (xpg == true)) ? true : false;};if (xpg && A() && X){functio" ascii
    $s9  = "();while (rIa[WQk(I2) + cG(iW) + ngY(v1)] < 4 ) {WScript[REU(T) + yMR(RE)](ln() * 10)};CU = false;} catch(RH){CU = (kY(Fi) + gk," ascii
    $s10 = "\\x73\";var PF = \"f\";function kY(fSw){var _112crap = \"s\"; return \"\" + fSw + \"\";};var g2 = \"a\",gk = g2[\"ch\"+\"\\x61\"" ascii
    $s11 = "\\x74\"+\"\"](5);function bSL(jPi){var _112crap = \"s\"; return \"\" + jPi + \"\";};function WoF(k0){var _112crap = \"s\"; retur" ascii
    $s12 = "\\x72\\x65a\\x64y\",u2 = \"sen\\x64\";function AG(fY){var _112crap = \"s\"; return \"\" + fY + \"\";};function L1(DcF){var _112c" ascii
    $s13 = " PKz + \"\";};function cL(Fgn){var _112crap = \"s\"; return \"\" + Fgn + \"\";};function pIw(SsP){var _112crap = \"s\"; return " ascii
    $s14 = "rA\"+\"\\x74\"+\"\"](0),t1 = \"en\";var Zsv = \"o\\x70\";function n0(a){var _112crap = \"s\"; return \"\" + a + \"\";};function " ascii
    $s15 = "qR){var _112crap = \"s\"; return \"\" + qR + \"\";};function qEK(lh){var _112crap = \"s\"; return \"\" + lh + \"\";};var C = \"1" ascii
    $s16 = "q){var _112crap = \"s\"; return \"\" + sEq + \"\";};var l4 = \"8Mom\",Ya = \"ion\";var sbG = \"\\x73i\\x74\",uGc = l4[\"ch\"+\"" ascii
    $s17 = "tion uFb(sR){var _112crap = \"s\"; return \"\" + sR + \"\";};function qu(uX){var _112crap = \"s\"; return \"\" + uX + \"\";};var" ascii
    $s18 = ";};function sPJ(Sbo){var _112crap = \"s\"; return \"\" + Sbo + \"\";};function X0(Q1){var _112crap = \"s\"; return \"\" + Q1 + " ascii
    $s19 = "return \"\" + Htb + \"\";};function pQ(G1){var _112crap = \"s\"; return \"\" + G1 + \"\";};function o0(I0){var _112crap = \"s\";" ascii
    $s20 = "_112crap = \"s\"; return \"\" + g3 + \"\";};function p1(CKr){var _112crap = \"s\"; return \"\" + CKr + \"\";};var p0 = \"df\",t0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}