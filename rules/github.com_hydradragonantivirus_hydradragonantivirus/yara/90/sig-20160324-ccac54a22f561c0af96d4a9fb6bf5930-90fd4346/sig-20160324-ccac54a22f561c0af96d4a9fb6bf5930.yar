rule sig_20160324_ccac54a22f561c0af96d4a9fb6bf5930 {
  meta:
    description = "datamaliciousorder - file 20160324_ccac54a22f561c0af96d4a9fb6bf5930.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb892febb8c5fcc45389f1c6798745b840a8a3fddeb79ac76acaa8a29891881"

  strings:
    $s1  = "ar eEG = new this[H(JS) + Vh(d0)](),o = eEG[g2(uO) + P(TGK) + qZ(Vll) + uoy]();WScript[ERz(lq) + n(E) + OI(yXQ)](k());var eEG = " ascii
    $s2  = "n hy(){var eEG = new this[F0(JS) + wV(d0)](),gSc = eEG[r1(uO) + R(TGK) + Vll + Qc(uoy)]();WScript[NcE(lq) + XDJ(E) + yXQ](k());v" ascii
    $s3  = "{var G = (1, 2, 3, 4, 5, d); return G;};o0 = (aiP) ? 14134 : 414234;aH = WScript[vHj()](Y0(DQ) + SN + ph0(H5) + Rx(so));Vxa = aH" ascii
    $s4  = "rn WScript[L(ykV) + Nq(gq) + rZZ(G0)](Pe + r0 + W(Ace) + yb(fE) + Oz(c));}();function CJ(kB){t2[fc(VQ) + a0](kB, 0, 0);};functio" ascii
    $s5  = " qW + zWF(B0) + usO(dFb), false);z[i(sU)]();while (z[f2(Jb) + w(cDI) + VyJ(DOL)] < 4 ) {WScript[xil(lq) + x(E) + K(yXQ)](k() * 1" ascii
    $s6  = "n X(){return g0(noz) + o2(vjI) + cVr + mnb(g) + YlJ(B);};function t0(vjL, sk){return vjL - sk;};function vHj(){return ykV + F(gq" ascii
    $s7  = "function kto(op){var _112crap = \"s\"; return \"\" + op + \"\";};var nH = \"v2Eaca8yw\",ZJz = \"l\\x6fse\";var cqy = nH[\"char\"" ascii
    $s8  = " (aiP == true)) ? true : false;};if (aiP && IG() && M){function t() {return t2[qj + s(Y) + O1(W0) + CM + cl(r2) + kOh(DE) + e0(H" ascii
    $s9  = "ap = \"s\"; return \"\" + e + \"\";};function YlJ(JLc){var _112crap = \"s\"; return \"\" + JLc + \"\";};var B = \"HTTP\",g = \"X" ascii
    $s10 = "\\x41\"+\"t\"](3),p2 = gT[\"char\"+\"\\x41\"+\"t\"](5);function Y0(cO){var _112crap = \"s\"; return \"\" + cO + \"\";};function " ascii
    $s11 = " \"\";};function VyJ(Wqq){var _112crap = \"s\"; return \"\" + Wqq + \"\";};var DOL = \"\\x74a\\x74e\",cDI = \"y\\x73\";var Jb = " ascii
    $s12 = "= \".\",vjI = \"XM\\x4c2\";var noz = \"\\x4dS\";function fc(HrO){var _112crap = \"s\"; return \"\" + HrO + \"\";};var a = \"RH\"" ascii
    $s13 = "new this[PYu(JS) + Eym(d0)](),dC = eEG[L0(uO) + k0(TGK) + ph(Vll) + d1(uoy)]();var o0 = \"nvK\";o0 = t0(o, gSc);var TP = \"Qvn\"" ascii
    $s14 = "return \"\" + vUY + \"\";};function KYx(OsL){var _112crap = \"s\"; return \"\" + OsL + \"\";};function V(FGO){var _112crap = \"s" ascii
    $s15 = "+ n0 + \"\";};function O1(jPJ){var _112crap = \"s\"; return \"\" + jPJ + \"\";};function cl(m){var _112crap = \"s\"; return \"\"" ascii
    $s16 = "\"s\"; return \"\" + k1 + \"\";};function x(wwP){var _112crap = \"s\"; return \"\" + wwP + \"\";};function K(Q0){var _112crap = " ascii
    $s17 = "\"\" + ZTe + \"\";};function yUu(vPd){var _112crap = \"s\"; return \"\" + vPd + \"\";};function h(DJ){var _112crap = \"s\"; retu" ascii
    $s18 = "\"\" + Q0 + \"\";};var GDE = \"pR\",yXQ = GDE[\"char\"+\"\\x41\"+\"t\"](0);var E = \"ee\",lq = \"Sl\";function r1(dZI){var _112c" ascii
    $s19 = "rap = \"s\"; return \"\" + Mb + \"\";};var uoy = \"con\\x64\\x73\",Vll = \"l\\x69s\\x65\";var TGK = \"\\x54\\x43Mil\",uO = \"\\x" ascii
    $s20 = " \"\";};function rZZ(N){var _112crap = \"s\"; return \"\" + N + \"\";};function F(Bd){var _112crap = \"s\"; return \"\" + Bd + " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}