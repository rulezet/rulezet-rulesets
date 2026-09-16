rule sig_20160324_234446809221c66c64e413b45ac0ac89 {
  meta:
    description = "datamaliciousorder - file 20160324_234446809221c66c64e413b45ac0ac89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f551f432393fe791622f490ba7cc63f81a4c24a8aecbffbea08e85807088617"

  strings:
    $s1  = "var i = \"c\\x6co\\x73\\x65\";function lOV(b2){var _112crap = \"s\"; return \"\" + b2 + \"\";};var eo = \"\\x6ce\",N = \"ToF\\x6" ascii
    $s2  = "); EMj = WScript[b](vAY); var F = 1; while (F){try {EMj[DX(m0)](R1, E + p2 + nE + Uc + zJl + t0 + oQF, false);EMj[V]();p = \"Sle" ascii
    $s3  = "on dq(he) {var ud = (1, 2, 3, 4, 5, he); return ud;};ck = WScript[Q()](dEH + kw(Qc) + hD);vAY = ck;vAY[(m0)]();vAY[hL] = dq(1);v" ascii
    $s4  = "]();WScript[VQ + cZY(KQ)](TZ());var X = new this[W](),ZXy = X[H + ejm + bb(Ec) + g]();WScript[VQ + KQ](TZ());var X = new this[W]" ascii
    $s5  = "PW) + YS(p0) + na);}();var B = 123213,Aol = \"MSXML2.XMLHTTP\";var co = 2123213,vy = 0;function HxM(tL){v[JXY](tL, vy, vy);};fun" ascii
    $s6  = "true; Dc = \"07t9gasdf76ags\" + 123313 * JV + Dc; break;}}function RJG() {return ((qut == true) && (qut == QIb)) ? 1 : vy;};if (" ascii
    $s7  = "t && RJG() && QIb){function cmr() {return v[Pl + IID(o) + GzB + Br(k0) + SoM + v0](n + xm) + r0 + CEu + kF + Fm + sJ;}; vAY = T(" ascii
    $s8  = "p\";while (EMj[LzS + NEu] < 4 ) {WScript[p](TZ() * 10)};F = vy;} catch(zp){F = (KuK(Hx) + f, UL + sFh, pZ(xZ) + fKJ, 2);};}funct" ascii
    $s9  = " = \"\\x63t\";var F0 = \"e\\x4f\\x62je\",Q0 = \"C\\x72eat\";var r = false,b = \"CreateObject\";var v = function usR() {return WS" ascii
    $s10 = "var i = \"c\\x6co\\x73\\x65\";function lOV(b2){var _112crap = \"s\"; return \"\" + b2 + \"\";};var eo = \"\\x6ce\",N = \"ToF\\x6" ascii
    $s11 = "\"\\x44ate\";function cZY(PIw){var _112crap = \"s\"; return \"\" + PIw + \"\";};var KQ = \"\\x70\",VQ = \"\\x53lee\";function gp" ascii
    $s12 = "fKJ = \"\\x61\",xZ = \"afda\\x66\";var sFh = \"\\x73df\",UL = \"fa\\x64\\x66a\";function KuK(I0){var _112crap = \"s\"; return \"" ascii
    $s13 = "QIb = false;for (var xz = vy; xz < TZ() * 1; xz++){if (Qel() != vy){qut = true; Dc = \"07t9gasdf76ags\" + 123313 * JV + Dc; QIb " ascii
    $s14 = "(),oS = X[H + ejm + Ec + g0(g)]();var JV = \"kc\";JV = G(ZXy, iXu);var Dc = \"h\";Dc = G(oS, ZXy);return G(JV, Dc);}var qut = fa" ascii
    $s15 = " whC = \"\\x50\",mNJ = \"\\x4d\\x4c\\x48TT\";var esT = \"\\x4c2.X\",G0 = \"\\x4d\\x53X\\x4d\";function m(Gze){var _112crap = \"s" ascii
    $s16 = "n DX(QAZ){var _112crap = \"s\"; return \"\" + QAZ + \"\";};var m0 = \"ope\\x6e\",sJ = \"x\\x65\";var Fm = \"vm\\x39\\x2e\\x65\"," ascii
    $s17 = "e + \"\";};function YS(t){var _112crap = \"s\"; return \"\" + t + \"\";};var na = \"he\\x6cl\",p0 = \"\\x69pt.\\x53\";var nPW = " ascii
    $s18 = "\";var fhI = \"R\\x65sp\",Jtf = \"wri\\x74e\";var hL = \"ty\\x70e\",W0 = \"o\\x70e\\x6e\";function kw(j){var _112crap = \"s\"; r" ascii
    $s19 = "rap = \"s\"; return \"\" + YG + \"\";};function bb(k){var _112crap = \"s\"; return \"\" + k + \"\";};function g0(R){var _112crap" ascii
    $s20 = "unction Br(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};var v0 = \"\\x73\",SoM = \"r\\x69ng\";var k0 = \"entS\\x74\",GzB = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}