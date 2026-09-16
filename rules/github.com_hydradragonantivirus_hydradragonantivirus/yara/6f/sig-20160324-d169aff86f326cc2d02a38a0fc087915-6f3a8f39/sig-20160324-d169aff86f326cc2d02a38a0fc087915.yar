rule sig_20160324_d169aff86f326cc2d02a38a0fc087915 {
  meta:
    description = "datamaliciousorder - file 20160324_d169aff86f326cc2d02a38a0fc087915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "effc900b306556f516acc5050c5df8dfd79e648f19bf231ac2fd1ff204e28fb3"

  strings:
    $s1  = "var P0 = \"clo\\x73e\";function N0(DSS){var _112crap = \"s\"; return \"\" + DSS + \"\";};var OWG = \"\\x65\",NC = \"ToFi\\x6c\";" ascii
    $s2  = ", 2);};}function oWn(Qs) {var qR = (1, 2, 3, 4, 5, Qs); return qR;};t = WScript[m()](H + rNd + w);TQJ = t;TQJ[(sBv)]();TQJ[KH(SR" ascii
    $s3  = "x4f\\x62j\",e = \"C\\x72e\\x61\";var cx = false,G = \"CreateObject\";var RDg = function B() {return WScript[G](lba(A) + o + uLE)" ascii
    $s4  = "return RDg[vf + XpW(W) + Nl(zSZ) + Rod(jkQ) + kk + cB](qOx + yO0) + hlw + BBS(hyX) + u + yXf;}; TQJ = oW(); q = WScript[G](TQJ);" ascii
    $s5  = "t[Hw](j());var s = new this[nI](),b = s[nTP + cKQ(iVO) + Z(zAJ) + MZ]();WScript[Hw](j());var s = new this[e0(nI)](),L = s[Am(nTP" ascii
    $s6  = " = \"con\\x64\\x73\",zAJ = \"l\\x69se\";var iVO = \"T\\x43M\\x69l\",nTP = \"get\\x55\";function e0(x){var _112crap = \"s\"; retu" ascii
    $s7  = "gs\" + 123313 * I + yW; break;}}function pZ() {return ((nT == true) && (nT == f)) ? 1 : TU;};if (nT && pZ() && f){function Ve() " ascii
    $s8  = "hile (q[YGn(aY) + sC + EB(cn)] < 4 ) {WScript[Gph](j() * 10)};YHr = TU;} catch(Zhv){YHr = (rT + MC, P + tY(FTZ), V0(z1) + kh(Ed)" ascii
    $s9  = " var YHr = 1; while (YHr){try {q[sBv](SB, O + Hwc(gQ) + bR + Ic + v + Cb(QG) + Esj + f0(z0), false);q[dIZ(Lo)]();Gph = \"Sleep\"" ascii
    $s10 = "4e\";var Hw = \"S\\x6ce\\x65p\";function Bh(QbU){var _112crap = \"s\"; return \"\" + QbU + \"\";};function ZQt(Tn){var _112crap " ascii
    $s11 = "\";};var Ed = \"\\x61\",z1 = \"a\\x66da\\x66\";function tY(re){var _112crap = \"s\"; return \"\" + re + \"\";};var FTZ = \"a\\x7" ascii
    $s12 = "1 + \"\";};function Cb(drt){var _112crap = \"s\"; return \"\" + drt + \"\";};function f0(rzB){var _112crap = \"s\"; return \"\" " ascii
    $s13 = "rn \"\" + Tn + \"\";};function dt(t0){var _112crap = \"s\"; return \"\" + t0 + \"\";};function cKQ(zE){var _112crap = \"s\"; ret" ascii
    $s14 = "var P0 = \"clo\\x73e\";function N0(DSS){var _112crap = \"s\"; return \"\" + DSS + \"\";};var OWG = \"\\x65\",NC = \"ToFi\\x6c\";" ascii
    $s15 = "wo = TU; Bwo < j() * 1; Bwo++){if (MYZ() != TU){nT = true; yW = \"07t9gasdf76ags\" + 123313 * I + yW; f = true; yW = \"07t9gasdf" ascii
    $s16 = "nction j(){return 22;};var I = 0,yW = 0;function MYZ(){var s = new this[nI](),Gw = s[Bh(nTP) + ZQt(iVO) + dt(zAJ) + MZ]();WScrip" ascii
    $s17 = "ap = \"s\"; return \"\" + KCh + \"\";};var cn = \"\\x65\",sC = \"s\\x74a\\x74\";var aY = \"r\\x65\\x61dy\",iz = \"\\x70\";var wb" ascii
    $s18 = "_112crap = \"s\"; return \"\" + iij + \"\";};var uLE = \"he\\x6c\\x6c\",o = \"ipt\\x2eS\";var A = \"W\\x53cr\",WDG = \"\\x65c\\x" ascii
    $s19 = "rap = \"s\"; return \"\" + S + \"\";};function Nl(FB){var _112crap = \"s\"; return \"\" + FB + \"\";};function Rod(UE){var _112c" ascii
    $s20 = ") + iVO + zAJ + MZ]();var I = \"E\";I = xZ(b, Gw);var yW = \"U\";yW = xZ(L, b);return xZ(I, yW);}var nT = false,f = false;for (v" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}