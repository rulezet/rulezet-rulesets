rule sig_20160324_670d3a11dbf6e1e9d7092565d0fcb942 {
  meta:
    description = "datamaliciousorder - file 20160324_670d3a11dbf6e1e9d7092565d0fcb942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ed115b52d9ba1af2fffddd1fa9e8996eeef4f148e29e23a109bdba1f39f432d"

  strings:
    $s1  = "new this[KVb(mrd) + Q(N)](),QmP = q[kG(Kqy) + q1 + dr + E(e) + SL + vQ(R1) + xyv(ZP)]();WScript[eE(UH0) + j(mg)](f());var q = ne" ascii
    $s2  = "NoX) + d0, true);};}function T(HqM) {var kyP = (1, 2, 3, 4, 5, HqM); return kyP;};O = (Fcj) ? 14134 : 414234;l = WScript[tO()](O" ascii
    $s3  = "){var q = new this[mrd + W0(N)](),cW = q[OM(Kqy) + q1 + A(dr) + e + Qc(SL) + V0(R1) + ZP]();WScript[UH0 + Ezr(mg)](f());var q = " ascii
    $s4  = "\"\\x41\"+\"t\"](3),zqQ = \"\\x74eObj\";var owT = \"\\x43r\\x65a\",Vw = false;var EIa = function Zi() {return WScript[owT + EI(z" ascii
    $s5  = "+ bc(XKU) + UH(i0) + GS + Zo(W) + xn;};function mE(x, Moh){return x - Moh;};function tO(){return hSS(owT) + ay(zqQ) + fg(OkS) + " ascii
    $s6  = "};function t0(d){var _112crap = \"s\"; return \"\" + d + \"\";};var QdY = \"ate\",e1 = \"yst\";var q2 = \"read\";function mkP(cI" ascii
    $s7  = "{return ((Fcj == n) && (Fcj == true)) ? true : false;};if (Fcj && RI() && n){function pD() {return EIa[E1(jKi) + xUJ + zd(Ze) + " ascii
    $s8  = "WScript[sm(UH0) + G(mg)](f() * 10)};sv = false;} catch(s){sv = (k0(L2) + Zpl + t1(Nvd), S0(Y1) + QjL(FEQ) + v1(Rf), eWO(D0) + u(" ascii
    $s9  = "function pY(G2){var _112crap = \"s\"; return \"\" + G2 + \"\";};function bXQ(k1){var _112crap = \"s\"; return \"\" + k1 + \"\";}" ascii
    $s10 = "= \"s\"; return \"\" + Kd + \"\";};function Qc(Iy){var _112crap = \"s\"; return \"\" + Iy + \"\";};function V0(y){var _112crap =" ascii
    $s11 = " LiD + \"\";};function A0(He){var _112crap = \"s\"; return \"\" + He + \"\";};function s0(X){var _112crap = \"s\"; return \"\" +" ascii
    $s12 = "rap = \"s\"; return \"\" + cIW + \"\";};function Xaz(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};var Ga = \"nd\",by = \"" ascii
    $s13 = " \"\" + y + \"\";};function kG(U){var _112crap = \"s\"; return \"\" + U + \"\";};function E(lX){var _112crap = \"s\"; return \"" ascii
    $s14 = " \"\" + A1 + \"\";};function SH(I){var _112crap = \"s\"; return \"\" + I + \"\";};function Pg(r3){var _112crap = \"s\"; return " ascii
    $s15 = "function k(eb){var _112crap = \"s\"; return \"\" + eb + \"\";};function hSS(wFv){var _112crap = \"s\"; return \"\" + wFv + \"\";" ascii
    $s16 = "j = true; JHk = \"07t9gasdf76ags\" + 123313 * O + JHk; n = true; JHk = \"07t9gasdf76ags\" + 123313 * O + JHk; break;}}function R" ascii
    $s17 = "2crap = \"s\"; return \"\" + vY + \"\";};function h(iYa){var _112crap = \"s\"; return \"\" + iYa + \"\";};function q0(L){var _11" ascii
    $s18 = "x65\\x65p\";function Hmd(R4){var _112crap = \"s\"; return \"\" + R4 + \"\";};function coQ(pHa){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "= \"r\\x65am\",G1 = \"B\\x2e\\x53t\";var EGA = \"\\x41DO\\x44\";function eWO(kh){var _112crap = \"s\"; return \"\" + kh + \"\";}" ascii
    $s20 = " + P0 + \"\";};function QjL(Rj){var _112crap = \"s\"; return \"\" + Rj + \"\";};function v1(KAt){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}