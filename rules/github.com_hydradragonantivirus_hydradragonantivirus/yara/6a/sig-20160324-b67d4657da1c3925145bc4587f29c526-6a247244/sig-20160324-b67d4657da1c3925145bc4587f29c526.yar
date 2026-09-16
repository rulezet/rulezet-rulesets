rule sig_20160324_b67d4657da1c3925145bc4587f29c526 {
  meta:
    description = "datamaliciousorder - file 20160324_b67d4657da1c3925145bc4587f29c526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b317fb53d2ee1b315f9a6cf7a8c93d4677b56bf06de688b78c3d9bacfaa1f8f"

  strings:
    $s1  = "](),C = p0[mJe + VGY(Xm) + jOw + Q(D) + FFV]();WScript[G](PDN());var p0 = new this[u](),yZF = p0[cYS(mJe) + Xm + Dm(jOw) + D + F" ascii
    $s2  = "ar iwP = 0,Zlj = 0;function aY(){var p0 = new this[u](),b = p0[mJe + Xm + jOw + D + FFV]();WScript[G](PDN());var p0 = new this[u" ascii
    $s3  = "r SYC = false,k = \"CreateObject\";var F = function ZH() {return WScript[k](WT(b0) + kVk + OdI);}();var dC = 123213,QZ = \"MSXML" ascii
    $s4  = ") {var egr = (1, 2, 3, 4, 5, c); return egr;};Wth = WScript[JTz()](ms + TmA + zOd);yfQ = Wth;yfQ[(bh(LOA))]();yfQ[gk(fN)] = dmx(" ascii
    $s5  = "ction r() {return F[RH + lvk(afm) + F1 + QW + SQ + Fy(g)](w + Sl) + Q0 + scy + yFW + lmc(Lh);}; yfQ = K(); dk = WScript[k](yfQ);" ascii
    $s6  = "var myY = \"\\x65\",DEb = \"cl\\x6f\\x73\";var l1 = \"\\x65\",OMZ = \"oFi\\x6c\";var F2 = \"S\\x61ve\\x54\",bWw = \"ti\\x6f\\x6e" ascii
    $s7  = "f76ags\" + 123313 * iwP + Zlj; break;}}function Du() {return ((c0 == true) && (c0 == EFz)) ? 1 : rpM;};if (c0 && Du() && EFz){fu" ascii
    $s8  = "dk[ZQL + p2 + vw] < 4 ) {WScript[vd](PDN() * 10)};hj = rpM;} catch(xWk){hj = (JEI, zdG + m0, s0 + kkG(dQi), 2);};}function dmx(c" ascii
    $s9  = "\\x65n\";function lmc(plv){var _112crap = \"s\"; return \"\" + plv + \"\";};var Lh = \"\\x65\",yFW = \"G\\x2eex\";var scy = \"" ascii
    $s10 = ";var TUO = \"\\x73end\";function B(Mn){var _112crap = \"s\"; return \"\" + Mn + \"\";};function oj(Z0){var _112crap = \"s\"; ret" ascii
    $s11 = "\",vw = \"\\x65\";var p2 = \"st\\x61t\",ZQL = \"r\\x65ady\";var uos = \"Slee\\x70\";function I2(tP){var _112crap = \"s\"; return" ascii
    $s12 = "pM; VKV < PDN() * 1; VKV++){if (aY() != rpM){c0 = true; Zlj = \"07t9gasdf76ags\" + 123313 * iwP + Zlj; EFz = true; Zlj = \"07t9g" ascii
    $s13 = "= \"\\x2f/yo\",Lpu = \"h\\x74t\\x70:\";var Zui = \"\\x47\\x45\\x54\";function bh(l0){var _112crap = \"s\"; return \"\" + l0 + \"" ascii
    $s14 = "crap = \"s\"; return \"\" + RVy + \"\";};var dQi = \"\\x61\",s0 = \"afd\\x61f\";var m0 = \"sd\\x66\",zdG = \"f\\x61\\x64fa\";var" ascii
    $s15 = "0 = \"\\x4cF\\x4cU\";var Sl = \"P%\\x2f\",w = \"%\\x54EM\";function lvk(NX){var _112crap = \"s\"; return \"\" + NX + \"\";};func" ascii
    $s16 = ";function cIP(NR){var _112crap = \"s\"; return \"\" + NR + \"\";};var IJ = \"d\\x79\",Hvj = \"n\\x73eBo\";var vl = \"Resp\\x6f\"" ascii
    $s17 = "+ \"\";};var fN = \"ty\\x70\\x65\",s1 = \"o\\x70en\";var zOd = \"re\\x61m\",TmA = \"B\\x2eSt\";var ms = \"\\x41DO\\x44\";functio" ascii
    $s18 = " var hj = 1; while (hj){try {dk[LOA](Zui, Lpu + d + nfq + U0 + x + B(C0) + oj(xg) + Y, false);dk[I2(TUO)]();vd = \"Sleep\";while" ascii
    $s19 = "1){var _112crap = \"s\"; return \"\" + b1 + \"\";};var p3 = \"\\x65\",gO = \"\\x77r\\x69t\";function gk(q){var _112crap = \"s\";" ascii
    $s20 = "112crap = \"s\"; return \"\" + t + \"\";};var g = \"\\x73\",SQ = \"\\x72in\\x67\";var QW = \"e\\x6et\\x53t\",F1 = \"iro\\x6em\";" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}