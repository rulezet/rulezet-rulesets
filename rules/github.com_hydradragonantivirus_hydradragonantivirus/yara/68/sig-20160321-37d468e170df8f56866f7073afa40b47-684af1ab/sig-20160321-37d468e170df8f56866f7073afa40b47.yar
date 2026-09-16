rule sig_20160321_37d468e170df8f56866f7073afa40b47 {
  meta:
    description = "datamaliciousorder - file 20160321_37d468e170df8f56866f7073afa40b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "840567b1e022bbc4a2ca74709fdd5a1db944d0801d83dc32ecfcbf6c889b46a4"

  strings:
    $s1  = "function Ophi(VYqlV){return VYqlV;};function e0(YZ){return YZ;};var n = \"62\";var zgZf = \"81\";var bfS = \"21836\";var jHn = " ascii
    $s2  = " + eT + (function jpzaS(){return IXV;}())]();WScript[xnNPM(CnN) + v(q)](o());var mGPK = new this[ZUQJH(BIc) + (function poow(){r" ascii
    $s3  = "Dxs = CEd(); BZ = WScript[(function XCzNN(){return nL;}()) + (function zGehf(){return M;}()) + (function Piv(){return MHW;}()) +" ascii
    $s4  = "eturn EszGG;}())]();var QfUPB = mGPK[P0(XcIr) + oTK(HpX) + (function NG(){return BVUKX;}()) + ltKx(eT) + IXV]();WScript[(functio" ascii
    $s5  = "n ihp;}())]();while (BZ[q0 + (function ORGun(){return XN;}()) + (function D(){return z;}()) + NJsQ] < 4 ) {WScript[CnN + q](o() " ascii
    $s6  = "* 10)};R = false;} catch(e){};}PFvA = WScript[ZlQ()](Z0 + vzE(KSclZ) + L1(DEF) + s0(aW) + MTct(Z1));PFvA[(GN + (function sjU(){r" ascii
    $s7  = "](5);var s = function FMFK() {return WScript[(function P(){return nL;}()) + (function Byjy(){return M;}()) + (function FY(){retu" ascii
    $s8  = "\"charAt\"](4);var kC = \"MS\\x58\\x4d\\x4c\";var MZ = \"Run\";function W(RHH){return RHH;};function Vx(bEL){return bEL;};var w " ascii
    $s9  = ") + (function bPgRb(){return Kac;}()) + QYBhk(aizBm) + (function CN(){return J;}());};function etl(DgvRj, TXGg){return DgvRj - T" ascii
    $s10 = " * 1; oSf++){if (DXgte() != 0){MNGXY = true;jfm = true;break;}}function kV() {return MNGXY && jfm;};if (kV()){rNzO = s[XF(a) + L" ascii
    $s11 = "zWW(Gva) + h + Co + arpE(Noh) + (function U(){return kPF;}()) + (function lHbYJ(){return pfS;}())]((function hy(){return m0;}())" ascii
    $s12 = "harAt\"](1);var z = \"ta\\x74\";var XN = \"adys\";var q0 = \"\\x72e\";var ihp = \"d\";var gKyoh = \"\\x73\\x65n\";function NeFve" ascii
    $s13 = "nR5S\";var TUG = J0[\"charAt\"](0);var wFUng = \"p\\x65\";var pqkr = \"o\";function vzE(jjT){return jjT;};function L1(nro){retur" ascii
    $s14 = "3a\";var jbvZJ = \"ht\";var sP = \"\\x47ET\";function LSgL(bq){return bq;};var FIqmx = \"nExUd\";var WLFmQ = FIqmx[\"charAt\"](0" ascii
    $s15 = "l\\x65e\";var hJO = \"ds\";var F0 = \"\\x63on\";var L0 = \"se\";var Mhp = \"Milli\";var QUg = \"get\";var vfKt = \"\\x44a\\x74" ascii
    $s16 = "l0 = g[\"charAt\"](5);var zm = \"itio\";var GnLj = \"os\";var MZ0 = \"p\";function AdP(ZrXJT){return ZrXJT;};var ghLjF = \"\\x6f" ascii
    $s17 = "n OqL(sZC){return sZC;};var XrzKQ = \"iD96jChB\";var u = \"ject\";var MHW = \"\\x61\\x74eO\\x62\";var M = \"r\\x65\";var nL = Xr" ascii
    $s18 = "rl4v\";var l = w[\"charAt\"](5);var SAQm = \".Sh\\x65l\";var t = \"ri\\x70t\";var CV = \"\\x57Sc\";function tNKr(SONC){return SO" ascii
    $s19 = "eturn WLFmQ;}()))]();PFvA[hdvq] = 1;PFvA[ETl + (function tS(){return u0;}())](BZ[(function EgTbv(){return V;}()) + cvQI + AdP(HA" ascii
    $s20 = "DC(){return XcIr;}()) + HpX + BVUKX + (function armR(){return eT;}()) + (function GL(){return IXV;}())]();var TS = \"HbP\";TS = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}