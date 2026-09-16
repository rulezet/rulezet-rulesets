rule sig_20160323_e08217a0f380bfcbc15a8cfcac424519 {
  meta:
    description = "datamaliciousorder - file 20160323_e08217a0f380bfcbc15a8cfcac424519.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0abe74ba61e53058f3bbb28328c32982559bf94fcbfc2365ea36214eef025c87"

  strings:
    $s1  = "function Hq(y4){var _112crap = \"s\"; return \"\" + y4 + \"\";};function Pqy(CAs){var _112crap = \"s\"; return \"\" + CAs + \"\"" ascii
    $s2  = "* VdP + Jpw; t = true; Jpw = \"07t9gasdf76ags\" + 123313 * VdP + Jpw; break;}}function rd() {return ((aRQ == t) && (aRQ == true)" ascii
    $s3  = "H) + GOE + a(mP) + Dyv + Ok(M0) + Dbv]();WScript[Ml(Zq) + yJ](A());var IDm = new this[J(EAw) + qL(VQ) + OXn(nI)](),U = IDm[Fv(De" ascii
    $s4  = "false,lYN = function eEQ() {return WScript[Ctq(hrm) + tzE(QJ) + UFN(qDW) + Td + YA(PCy)](USX(k) + f(x) + zEf(GyE) + Z(lu) + qa(n" ascii
    $s5  = "c(GOE) + mP + Dyv + M0 + Znt(Dbv)]();WScript[W1(Zq) + A0(yJ)](A());var IDm = new this[y0(EAw) + o(VQ) + gCS(nI)](),wW = IDm[w(De" ascii
    $s6  = "? true : false;};if (aRQ && rd() && t){function zI() {return lYN[Z1 + rOU(dC) + y2 + sZ(jZ) + B(eK) + mwJ + z + K(P0)](c2(ZYA) +" ascii
    $s7  = "3 = \"fa\\x64\\x66\";function COM(Z2){var _112crap = \"s\"; return \"\" + Z2 + \"\";};function e2(jHM){var _112crap = \"s\"; ret" ascii
    $s8  = "= (COM(D) + e2(yKj) + Rr(h4), n3 + i0(f2) + E1(Io), P3 + zgP, true);};}function Bpt(Uh) {var M = (1, 2, 3, 4, 5, Uh); return M;}" ascii
    $s9  = "Ap(glA), false);lF[JSc(j1)]();while (lF[KeP + e(w0) + PGI(w1)] < 4 ) {WScript[P(Zq) + yJ](A() * 10)};pmE = false;} catch(I){pmE " ascii
    $s10 = "\\x65\\x61t\";function TB(WbG){var _112crap = \"s\"; return \"\" + WbG + \"\";};function f0(Ou){var _112crap = \"s\"; return \"" ascii
    $s11 = "\"\";};function FAp(CG){var _112crap = \"s\"; return \"\" + CG + \"\";};var gDs = \"8dVKAaC3NoG\",glA = gDs[\"\"+\"\\x63\"+\"h\"" ascii
    $s12 = "urn \"\" + e4 + \"\";};var pmt = \"\\x69le\",D1 = \"o\\x46\";var D0 = \"\\x53\\x61v\\x65T\";function hb(MYa){var _112crap = \"s" ascii
    $s13 = "rap = \"s\"; return \"\" + i + \"\";};var w1 = \"te\",w0 = \"\\x79sta\";var KeP = \"r\\x65a\\x64\";function JSc(P2){var _112crap" ascii
    $s14 = "a + \"\";};function jAn(QG){var _112crap = \"s\"; return \"\" + QG + \"\";};var Z3 = \"n\",R0 = \"\\x74io\";var bBT = \"\\x70osi" ascii
    $s15 = "_112crap = \"s\"; return \"\" + jJ + \"\";};function E1(e3){var _112crap = \"s\"; return \"\" + e3 + \"\";};var Io = \"f\",f2 = " ascii
    $s16 = "6\",y3 = \"htt\\x70\";function r1(XA){var _112crap = \"s\"; return \"\" + XA + \"\";};var gxi = \"GE\\x54\";function eA(EWE){var" ascii
    $s17 = "var zGu = \"en\",vq = \"op\";function Pg(cox){var _112crap = \"s\"; return \"\" + cox + \"\";};function JKJ(yJ0){var _112crap = " ascii
    $s18 = "rn \"\" + pV + \"\";};function scL(BJL){var _112crap = \"s\"; return \"\" + BJL + \"\";};var FFG = \"ite\",BV = \"w\\x72\";funct" ascii
    $s19 = "\"\" + P2 + \"\";};var j1 = \"\\x73end\";function EwQ(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};function FHC(cz){var _" ascii
    $s20 = "+ \"\";};function gCS(h0){var _112crap = \"s\"; return \"\" + h0 + \"\";};function J(k0){var _112crap = \"s\"; return \"\" + k0 " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}