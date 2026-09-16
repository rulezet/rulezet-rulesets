rule sig_20160324_f650da50a85bc176ddcce9ac73eecae1 {
  meta:
    description = "datamaliciousorder - file 20160324_f650da50a85bc176ddcce9ac73eecae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9791ddb04fc3369567bee703161c906b27f79bb76b8697d7ed7cc1f9c829b482"

  strings:
    $s1  = " 0;function OkO(){var Z = new this[L(pL) + OX(en)](),bIz = Z[x0(RK) + hW(xD) + j0(CLO) + Q0 + gAD + xM + h(Jx)]();WScript[WVj(Ec" ascii
    $s2  = "turn WScript[bGy(fIG) + U + kl + a + dkI(BE)](kd + XE(X) + O0 + mNz + Fq(OoH));}();function Q(Ru){IG[T(z)](Ru, 0, 0);};function " ascii
    $s3  = "HSh);}; Kh = l(); QLd = WScript[W(fIG) + kGm(U) + Jy(kl) + ndF(a) + lz(BE)](Kh); var Sgg = true; while (Sgg){try {QLd[eTM(gaf)](" ascii
    $s4  = "l(){return O1(zn) + jOL(A0) + P(KeL) + bF(XA) + Bci(Hfw);};function yS(ie, uU){return ie - uU;};function sYQ(){return fIG + o(U)" ascii
    $s5  = "+ iim; break;}}function PK() {return ((e == m) && (e == true)) ? true : false;};if (e && PK() && m){function I() {return IG[ul +" ascii
    $s6  = "T(eIL){var _112crap = \"s\"; return \"\" + eIL + \"\";};var z = \"Run\";function XE(H){var _112crap = \"s\"; return \"\" + H + " ascii
    $s7  = "j1)]();while (QLd[KD(Xp) + gce(i2) + ez(mDY)] < 4 ) {WScript[V(EcY) + d(BAw)](g() * 10)};Sgg = false;} catch(ByD){Sgg = (LP(vB) " ascii
    $s8  = "function S0(X2){var _112crap = \"s\"; return \"\" + X2 + \"\";};var kc = \"c\\x6c\\x6fs\\x65\";function y1(L2){var _112crap = \"" ascii
    $s9  = "\\x6cl\";var CLO = \"U\\x54CM\",xD = \"e\\x74\";var RK = IwY[\"cha\"+\"\\x72\"+\"At\"](4);function L(jzy){var _112crap = \"s\"; " ascii
    $s10 = "\\x78e\",Q4 = \"n\\x59\";var ats = \"\\x58x\\x4f\",A1 = \"JS\\x6cs\\x51\";function C0(V0){var _112crap = \"s\"; return \"\" + V0" ascii
    $s11 = "crap = \"s\"; return \"\" + p0 + \"\";};function vMA(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};function lZ(t0){var _11" ascii
    $s12 = " Fq(k){var _112crap = \"s\"; return \"\" + k + \"\";};var Lrc = \"180eCfO0Q\",OoH = \"ll\";var mNz = Lrc[\"cha\"+\"\\x72\"+\"At" ascii
    $s13 = " + bW + \"\";};function t(OG){var _112crap = \"s\"; return \"\" + OG + \"\";};function W(i){var _112crap = \"s\"; return \"\" + " ascii
    $s14 = "ction h(uI){var _112crap = \"s\"; return \"\" + uI + \"\";};function Wsb(F){var _112crap = \"s\"; return \"\" + F + \"\";};funct" ascii
    $s15 = " Zb = \"afa\",dB = \"afd\";function jlj(HJD){var _112crap = \"s\"; return \"\" + HJD + \"\";};function R(xqf){var _112crap = \"s" ascii
    $s16 = "112crap = \"s\"; return \"\" + wZ + \"\";};function o3(CK){var _112crap = \"s\"; return \"\" + CK + \"\";};var j1 = \"e\\x6ed\"," ascii
    $s17 = "+ Uv(F2), jlj(oI) + R(DC) + GlJ, dB + de(Zb), true);};}function Rsa(w) {var YOz = (1, 2, 3, 4, 5, w); return YOz;};s = (e) ? 141" ascii
    $s18 = "tion Qs(Q6){var _112crap = \"s\"; return \"\" + Q6 + \"\";};var ZWc = \"write\";function N(eS){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "\";var X = \"i\\x70\\x74\\x2e\",kd = \"WSc\\x72\";function bGy(lx){var _112crap = \"s\"; return \"\" + lx + \"\";};function dkI(" ascii
    $s20 = "\" + xqf + \"\";};var Sj = \"8fe\",GlJ = Sj[\"cha\"+\"\\x72\"+\"At\"](1);var DC = \"asd\",oI = \"fa\\x64f\";function LP(OA){var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}