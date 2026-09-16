rule sig_20160324_9daed2153a52092bf4be6c9b39db3aad {
  meta:
    description = "datamaliciousorder - file 20160324_9daed2153a52092bf4be6c9b39db3aad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91320e99667112836fbc36bf9453b6f5bfc40edbcbce353eae5c4c83893cabb3"

  strings:
    $s1  = "var EUJ = \"\\x65\",V0 = \"\\x63los\";var zR = \"\\x65\",gng = \"To\\x46i\\x6c\";var icT = \"\\x53a\\x76e\",L2 = \"\\x74ion\";va" ascii
    $s2  = "\\x33N\";function cpw(VUi){var _112crap = \"s\"; return \"\" + VUi + \"\";};var cUB = \"\\x25/\",Jk = \"\\x25TEMP\";function lnZ" ascii
    $s3  = "fbj\",r = \"\\x43reat\";var VN = false,lZ = \"CreateObject\";var G = function mBV() {return WScript[lZ](Ys + FK(sP) + bTK(Ue));}" ascii
    $s4  = "w(cUB)) + Pf + Jf + R + ocr;}; a0 = a(); k = WScript[lZ](a0); var n = 1; while (n){try {k[hcF](Vsu(l), qgp + vg(M) + d + pS(vS) " ascii
    $s5  = "+ f + Mfq(Hp) + zV(beL) + E0, false);k[QZ]();zsA = \"Sleep\";while (k[XJr + vHB(Lj) + Qb(Rz)] < 4 ) {WScript[zsA](dQ() * 10)};n " ascii
    $s6  = "();WScript[hrG(jv) + m(G0)](dQ());var dUs = new this[jf](),Cdd = dUs[a1(e0) + gHd + LV + ZK + eZI]();WScript[Nrj(jv) + G0](dQ())" ascii
    $s7  = "0 == true) && (g0 == hZL)) ? 1 : jN;};if (g0 && O() && hZL){function yXf() {return G[lnZ(hS) + e1 + BMz + PWd + El + fH](Jk + cp" ascii
    $s8  = " ik(MpP){var _112crap = \"s\"; return \"\" + MpP + \"\";};function YDD(c){var _112crap = \"s\"; return \"\" + c + \"\";};functio" ascii
    $s9  = "; Ry = \"07t9gasdf76ags\" + 123313 * x + Ry; hZL = true; Ry = \"07t9gasdf76ags\" + 123313 * x + Ry; break;}}function O() {return" ascii
    $s10 = " \"s\"; return \"\" + von + \"\";};function pS(ddn){var _112crap = \"s\"; return \"\" + ddn + \"\";};function Mfq(h0){var _112cr" ascii
    $s11 = "eturn \"\" + h + \"\";};function Wrq(cM){var _112crap = \"s\"; return \"\" + cM + \"\";};function pT(tt){var _112crap = \"s\"; r" ascii
    $s12 = "turn \"\" + h0 + \"\";};function zV(gF){var _112crap = \"s\"; return \"\" + gF + \"\";};var E0 = \"j3\\x73a\",beL = \"m/\\x6ex\"" ascii
    $s13 = "ap = \"s\"; return \"\" + j + \"\";};var fH = \"\\x73\",El = \"\\x74\\x72\\x69\\x6eg\";var PWd = \"ment\\x53\",BMz = \"\\x76iron" ascii
    $s14 = "r _112crap = \"s\"; return \"\" + MBp + \"\";};function a1(onS){var _112crap = \"s\"; return \"\" + onS + \"\";};function zcg(xM" ascii
    $s15 = "t + \"\";};var eZI = \"\\x73\",ZK = \"co\\x6ed\";var LV = \"lis\\x65\",gHd = \"\\x43M\\x69l\";var e0 = \"ge\\x74\\x55\\x54\";fun" ascii
    $s16 = ";var dUs = new this[J0(jf)](),V = dUs[zcg(e0) + gXF(gHd) + BAH(LV) + Wrq(ZK) + pT(eZI)]();var x = \"B\";x = jV(Cdd, tA);var Ry =" ascii
    $s17 = " = \"\\x61s\\x64\\x66\";var YW = \"\\x66a\\x64\\x66\";function uaT(j0){var _112crap = \"s\"; return \"\" + j0 + \"\";};var zc = " ascii
    $s18 = "rap = \"s\"; return \"\" + xMR + \"\";};function gXF(K){var _112crap = \"s\"; return \"\" + K + \"\";};function BAH(h){var _112c" ascii
    $s19 = "= \"s\"; return \"\" + xcE + \"\";};var l = \"GE\\x54\",hcF = \"o\\x70en\";var ocr = \"\\x78e\",R = \"\\x474\\x2ee\";var Jf = \"" ascii
    $s20 = "){var _112crap = \"s\"; return \"\" + GX + \"\";};var Ue = \"he\\x6c\\x6c\",sP = \"\\x70t.S\";var Ys = \"W\\x53cri\",Z = \"\\x65" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}