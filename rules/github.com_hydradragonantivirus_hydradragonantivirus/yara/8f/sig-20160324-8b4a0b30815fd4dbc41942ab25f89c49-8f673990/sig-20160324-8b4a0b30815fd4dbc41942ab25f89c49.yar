rule sig_20160324_8b4a0b30815fd4dbc41942ab25f89c49 {
  meta:
    description = "datamaliciousorder - file 20160324_8b4a0b30815fd4dbc41942ab25f89c49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e30878491b8d98edfffb4cfc6f043980f197dcc94492523e41335da9b565f4e"

  strings:
    $s1  = "var PN = \"\\x63lose\";function L0(Zi){var _112crap = \"s\"; return \"\" + Zi + \"\";};var Xfh = \"l\\x65\",HW = \"ToF\\x69\";va" ascii
    $s2  = "[bU(TgE) + Q](kY());var gh = new this[sjh](),mnb = gh[s + Fl + m0 + J]();WScript[YST(TgE) + Q](kY());var gh = new this[sjh](),iP" ascii
    $s3  = "= \"t\\x65\\x4fbj\",Pav = \"\\x43rea\";var z = false,ehf = \"CreateObject\";var Ycd = function L() {return WScript[ehf](S + x + " ascii
    $s4  = "r(RbK) {var OD = (1, 2, 3, 4, 5, RbK); return OD;};i = WScript[AOs()](l + c(zN) + LVA);D = i;D[(Az)]();D[KC(Uo)] = RCr(1);D[Ng](" ascii
    $s5  = "f (z){function kY(){return 22;};var zu = 0,WX = 0;function M(){var gh = new this[sjh](),INX = gh[YrI(s) + Fl + m0 + J]();WScript" ascii
    $s6  = "k() && a){function xA() {return Ycd[sg + DMu + Ra + A + Klx + W0](CST(B) + sBX(UY)) + u2 + hc + C(dR);}; D = gY(); CVf = WScript" ascii
    $s7  = "rue; WX = \"07t9gasdf76ags\" + 123313 * zu + WX; break;}}function aUk() {return ((mY == true) && (mY == a)) ? 1 : m;};if (mY && " ascii
    $s8  = "(CVf[jK + FH0(SV) + vi] < 4 ) {WScript[y](kY() * 10)};uc = m;} catch(xC){uc = (h + M0, f(iA) + j, Vo + Wbu(p), 2);};}function RC" ascii
    $s9  = " \"Sl\\x65ep\";var jo = \"\\x64s\",Y0 = \"\\x65c\\x6f\\x6e\";var cUy = \"lli\\x73\",nEY = \"\\x54CMi\";var F = \"get\\x55\",K = " ascii
    $s10 = "\\x6cee\";function YrI(SG){var _112crap = \"s\"; return \"\" + SG + \"\";};function ej(TTO){var _112crap = \"s\"; return \"\" + " ascii
    $s11 = "s\"; return \"\" + an + \"\";};var MDX = \"R\\x75n\",uu = \"\\x50\";var u1 = \"L\\x48TT\",u0 = \"L\\x32\\x2eX\\x4d\";var AX = \"" ascii
    $s12 = "[ehf](D); var uc = 1; while (uc){try {CVf[Az](Xo, mGy(Vf) + RvQ + igH(mwS) + C0 + Had + ilg, false);CVf[ag]();y = \"Sleep\";whil" ascii
    $s13 = "alse,a = false;for (var zqt = m; zqt < kY() * 1; zqt++){if (M() != m){mY = true; WX = \"07t9gasdf76ags\" + 123313 * zu + WX; a =" ascii
    $s14 = "o = gh[ej(s) + Fl + m0 + J]();var zu = \"fGP\";zu = Qer(mnb, INX);var WX = \"Cst\";WX = Qer(iPo, mnb);return Qer(zu, WX);}var mY" ascii
    $s15 = "ion C(F1){var _112crap = \"s\"; return \"\" + F1 + \"\";};var dR = \"\\x78.\\x65xe\",hc = \"\\x715P\\x6cT\";var u2 = \"iyy\\x64Q" ascii
    $s16 = "u(k){var _112crap = \"s\"; return \"\" + k + \"\";};var p = \"\\x61\",Vo = \"afda\\x66\";function f(R0){var _112crap = \"s\"; re" ascii
    $s17 = "var PN = \"\\x63lose\";function L0(Zi){var _112crap = \"s\"; return \"\" + Zi + \"\";};var Xfh = \"l\\x65\",HW = \"ToF\\x69\";va" ascii
    $s18 = "U(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function YST(FH){var _112crap = \"s\"; return \"\" + FH + \"\";};var Q = \"" ascii
    $s19 = "q(Jq){var _112crap = \"s\"; return \"\" + Jq + \"\";};var Uh = \"he\\x6cl\",x = \"pt\\x2eS\";var S = \"WS\\x63\\x72\\x69\",KVB =" ascii
    $s20 = "5\";function U(SG0){var _112crap = \"s\"; return \"\" + SG0 + \"\";};function Qi(gRj){var _112crap = \"s\"; return \"\" + gRj + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}