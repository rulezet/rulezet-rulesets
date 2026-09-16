rule sig_20160324_c728ad34a70636f936ecab34a34787fc {
  meta:
    description = "datamaliciousorder - file 20160324_c728ad34a70636f936ecab34a34787fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf436a7d037a34f69400c67491698e83218f5681ceec6bd275fa7dbc18cd6be"

  strings:
    $s1  = "function WB(HRW){var _112crap = \"s\"; return \"\" + HRW + \"\";};function B(dRw){var _112crap = \"s\"; return \"\" + dRw + \"\"" ascii
    $s2  = "WScript[cqi + Yt(us)](Q());var KT = new this[vrR](),r0 = KT[K + q + LK + iST]();WScript[cqi + us](Q());var KT = new this[vrR]()," ascii
    $s3  = "function wI() {return o[OBB(q0) + VbN + V1 + G0 + YZC(H)](KU + Ep) + Hj(jV) + qz0 + pJc + gK;}; dFu = s(); Kp = WScript[C](dFu);" ascii
    $s4  = " {var RJ = (1, 2, 3, 4, 5, d); return RJ;};m = WScript[G()](JQa + lU + C0);dFu = m;dFu[(Z)]();dFu[cl] = oa(1);dFu[A + z(YaI)](Kp" ascii
    $s5  = "(uc + S + GD);}();var l = 123213,TE = \"MSXML2.XMLHTTP\";var BT = 2123213,r = 0;function nO(D){o[RB(myd)](D, r, r);};function s(" ascii
    $s6  = "aoy = \"07t9gasdf76ags\" + 123313 * ZD + aoy; break;}}function h() {return ((V == true) && (V == M)) ? 1 : r;};if (V && h() && M" ascii
    $s7  = "y(Pv) + ptw] < 4 ) {WScript[L](Q() * 10)};wv = r;} catch(td){wv = (zwK(MaO) + La(kST), y + gsk, l0 + k(Kk), 2);};}function oa(d)" ascii
    $s8  = "9\",d0 = \"e\\x63t\";var F = \"\\x74eO\\x62j\",qz = \"\\x43rea\";var xB = false,C = \"CreateObject\";var o = function rb() {retu" ascii
    $s9  = "T = \"on\\x64s\";var th = \"\\x69s\\x65c\",f = \"\\x43Mill\";var V0 = \"getU\\x54\",J = \"\\x44ate\";function Yt(eP){var _112cra" ascii
    $s10 = "function WB(HRW){var _112crap = \"s\"; return \"\" + HRW + \"\";};function B(dRw){var _112crap = \"s\"; return \"\" + dRw + \"\"" ascii
    $s11 = " \"\\x65\",ttj = \"cl\\x6fs\";var E0 = \"\\x65\",PHE = \"ToF\\x69l\";var l1 = \"S\\x61ve\";function YJ(X){var _112crap = \"s\"; " ascii
    $s12 = "e,M = false;for (var Wg = r; Wg < Q() * 1; Wg++){if (CF() != r){V = true; aoy = \"07t9gasdf76ags\" + 123313 * ZD + aoy; M = true" ascii
    $s13 = "ar gsk = \"\\x61sdf\",y = \"f\\x61df\";function zwK(tq){var _112crap = \"s\"; return \"\" + tq + \"\";};function La(NWh){var _11" ascii
    $s14 = "8u\";var rF = \"ht\\x74p\",iR = \"\\x47ET\";function q1(vL){var _112crap = \"s\"; return \"\" + vL + \"\";};var Z = \"\\x6fpe\\x" ascii
    $s15 = "12crap = \"s\"; return \"\" + oz + \"\";};var iST = \"c\\x6fnd\\x73\",LK = \"\\x6c\\x69\\x73\\x65\";var q = \"T\\x43\\x4d\\x69l" ascii
    $s16 = "crap = \"s\"; return \"\" + C1 + \"\";};var YaI = \"\\x65\",A = \"w\\x72it\";var cl = \"t\\x79pe\",aNu = \"o\\x70\\x65\\x6e\";va" ascii
    $s17 = "mR = KT[K + N0(q) + LK + iST]();var ZD = \"DIS\";ZD = Q0(r0, bJ);var aoy = \"ssE\";aoy = Q0(mR, r0);return Q0(ZD, aoy);}var V = " ascii
    $s18 = "turn \"\" + Iu + \"\";};var pgU = \"\\x64\",xj = \"9s\\x6ba\";var cX = \"m/\\x6b3\",dG = \"\\x67\\x6e.co\";var Fh = \"d\\x65si\"" ascii
    $s19 = " return \"\" + NWh + \"\";};var kST = \"\\x61\",MaO = \"a\\x73d\\x66\";function gy(f0){var _112crap = \"s\"; return \"\" + f0 + " ascii
    $s20 = "*/if (xB){function Q(){return 22;};var ZD = 0,aoy = 0;function CF(){var KT = new this[po(vrR)](),bJ = KT[K + N(q) + LK + iST]();" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}