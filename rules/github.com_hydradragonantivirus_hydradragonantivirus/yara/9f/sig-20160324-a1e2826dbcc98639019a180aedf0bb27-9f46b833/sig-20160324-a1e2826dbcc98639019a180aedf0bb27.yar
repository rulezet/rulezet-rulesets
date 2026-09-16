rule sig_20160324_a1e2826dbcc98639019a180aedf0bb27 {
  meta:
    description = "datamaliciousorder - file 20160324_a1e2826dbcc98639019a180aedf0bb27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "626451099b36b6fc5a49621dc0bf3dfcfdba7bec3627f2a4280935645672cd19"

  strings:
    $s1  = "function oVB(c1){var _112crap = \"s\"; return \"\" + c1 + \"\";};function R0(lw){var _112crap = \"s\"; return \"\" + lw + \"\";}" ascii
    $s2  = "turn 22;};var ZR = 0,HN = 0;function N(){var HkA = new this[T](),FR = HkA[K + TQ + slq + pdn(n)]();WScript[d](lz());var HkA = ne" ascii
    $s3  = "w this[hn(T)](),O0 = HkA[K + TQ + Ed(slq) + n]();WScript[d](lz());var HkA = new this[se(T)](),RH = HkA[W0(K) + TQ + slq + n]();v" ascii
    $s4  = "C\\x72ea\";var mr = false,VtA = \"CreateObject\";var MU = function O() {return WScript[VtA](RsR + dA + CP(sx));}();var eh = 1232" ascii
    $s5  = "); return wZ;};t = WScript[bv()](PCe + RpV + ltf);RMB = t;RMB[(X0(WXp))]();RMB[btp] = fo(1);RMB[Eq + oNF](B[C1 + z + fO(CZa)]);R" ascii
    $s6  = "return MU[c + DLm + XKT + s0(f0) + M](W1 + v) + tT(xO) + h0 + cY + kHM(R);}; RMB = TPK(); B = WScript[VtA](RMB); var yuE = 1; wh" ascii
    $s7  = "3313 * ZR + HN; break;}}function XPH() {return ((Pz == true) && (Pz == hvl)) ? 1 : PZ;};if (Pz && XPH() && hvl){function Ovw() {" ascii
    $s8  = "\\x65\\x54\",p = \"t\\x69\\x6fn\";var uV = \"\\x70osi\";function fO(Rh){var _112crap = \"s\"; return \"\" + Rh + \"\";};var CZa " ascii
    $s9  = "\\x69\",K = \"g\\x65tU\";function hn(Tm){var _112crap = \"s\"; return \"\" + Tm + \"\";};function se(YPa){var _112crap = \"s\"; " ascii
    $s10 = "6d/\",h1 = \"p\\x72ez\";var YcU = \"\\x3a//by\",oJt = \"\\x68\\x74tp\";var GDj = \"\\x47ET\";function X0(MM){var _112crap = \"s" ascii
    $s11 = "\" + Vt + \"\";};function W0(C){var _112crap = \"s\"; return \"\" + C + \"\";};var n = \"con\\x64\\x73\",slq = \"\\x6c\\x6cise\"" ascii
    $s12 = " = \"s\\x65nd\";function b(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};var X1 = \"l3\\x73\",cI = \"o\\x65\\x65\\x70s\";v" ascii
    $s13 = "f\";var Kk = \"\\x61s\\x64\\x66\",eoE = \"f\\x61df\";var f1 = \"a\\x73\\x64\\x66a\";function tN(w){var _112crap = \"s\"; return " ascii
    $s14 = "function oVB(c1){var _112crap = \"s\"; return \"\" + c1 + \"\";};function R0(lw){var _112crap = \"s\"; return \"\" + lw + \"\";}" ascii
    $s15 = "Pa + \"\";};var T = \"Dat\\x65\",LsS = \"Ru\\x6e\";var tGA = \"\\x48TTP\",h = \"2.XM\\x4c\";var YEN = \"M\\x53XML\";function CP(" ascii
    $s16 = "UN < lz() * 1; JUN++){if (N() != PZ){Pz = true; HN = \"07t9gasdf76ags\" + 123313 * ZR + HN; hvl = true; HN = \"07t9gasdf76ags\" " ascii
    $s17 = "50\";function s0(dy){var _112crap = \"s\"; return \"\" + dy + \"\";};var M = \"ri\\x6e\\x67s\",f0 = \"en\\x74S\\x74\";var XKT = " ascii
    $s18 = "r o = \"s\\x74ate\",qVZ = \"\\x72e\\x61d\\x79\";var SHk = \"\\x53leep\";function wkA(EYZ){var _112crap = \"s\"; return \"\" + EY" ascii
    $s19 = "\"Da\\x74e\",d = \"Slee\\x70\";function pdn(G0){var _112crap = \"s\"; return \"\" + G0 + \"\";};function Ed(Vt){var _112crap = " ascii
    $s20 = "ile (yuE){try {B[WXp](GDj, oJt + YcU + h1 + uR + b(cI) + X1, false);B[wkA(Na)]();Rjn = \"Sleep\";while (B[tN(qVZ) + o] < 4 ) {WS" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}