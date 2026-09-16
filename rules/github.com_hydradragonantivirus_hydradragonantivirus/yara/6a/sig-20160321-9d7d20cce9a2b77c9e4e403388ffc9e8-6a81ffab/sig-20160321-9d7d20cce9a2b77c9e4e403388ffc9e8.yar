rule sig_20160321_9d7d20cce9a2b77c9e4e403388ffc9e8 {
  meta:
    description = "datamaliciousorder - file 20160321_9d7d20cce9a2b77c9e4e403388ffc9e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1fe4c63b4156da3a0a193b4d22df851c0d887fe4cc5cead01e018220bf72a82"

  strings:
    $s1  = "var t2 = \"20WOAG\";var oE = t2[\"c\\x68arAt\"](0);var ZqOom = \"1\\x36\";var Jnk = \"6\\x38\";var B0 = \"\\x32183\";var X0 = \"" ascii
    $s2  = " XgwWp = \"a\\x74\";var h = \"Cre\";var YhEp = function r() {return WScript[(function zR(){return h;}()) + nViZ(XgwWp) + zG(srqp" ascii
    $s3  = "+ (function nLTfM(){return Uk;}()) + (function nCsv(){return tYz;}()) + (function jig(){return TuV;}()) + kQ(Id)] < 4 ) {WScript" ascii
    $s4  = "HA) + An(elrg) + OeMX; XIs = up(); v = WScript[q(h) + XgwWp + (function EHxb(){return srqpi;}()) + kEoda + nQo + Sb(mqopc)](XIs)" ascii
    $s5  = " GXFyv;}()) + HN(zYvtr) + zG0(GVZ) + (function C(){return EdrW;}())]();WScript[xAb + Cp(Fn)](o());var idXg = new this[(function " ascii
    $s6  = "return GXFyv;}()) + (function keXG(){return zYvtr;}()) + GVZ + EdrW]();WScript[(function rEdZt(){return xAb;}()) + (function ani" ascii
    $s7  = "aKOH\";var t = \"ll\";var ewHkb = \"\\x74.She\";var iwFOI = \"S\\x63rip\";var adP = Sv[\"c\\x68arAt\"](4);function nViZ(wVZx){re" ascii
    $s8  = "r, bJMe){return tCSir - bJMe;};function dND(){return h + SP(XgwWp) + (function uiKib(){return srqpi;}()) + zAIQ(kEoda) + Nga(nQo" ascii
    $s9  = "Dh = false;for (var S = 0; S < o() * 1; S++){if (PEgh() != 0){lKZZR = true;SUDh = true;break;}}function HTs() {return lKZZR && S" ascii
    $s10 = "[Dmr(xAb) + Fn](o() * 10)};OSTnl = false;} catch(e){};}PE = WScript[dND()](xANFI(gGB) + Lm(g0) + pVioZ(IwiNC) + rkNg(SAmG) + LNq" ascii
    $s11 = "n l(mP){return mP;};var XIdS = \"49CusHOom\";var EdrW = XIdS[\"c\\x68arAt\"](4);var GVZ = \"ec\\x6fn\\x64\";var zYvtr = \"l\\x69" ascii
    $s12 = "ar wUQqf = \"\\x6bj\";var U0 = \"\\x61\\x73dlf\";var a = \"8Q9e\";var QT = a[\"c\\x68arAt\"](3);var e = \"\\x73\";var OJ = \"\\x" ascii
    $s13 = "Sb(sqMr){return sqMr;};var thnMl = \"tEgh\";var mqopc = thnMl[\"c\\x68arAt\"](0);var nQo = \"ec\";var kEoda = \"bj\";var srqpi =" ascii
    $s14 = "UHSU){return UHSU;};function kQ(or){return or;};var Y1 = \"ZT4F3tE\";var Id = \"\\x74\\x65\";var TuV = \"a\";var tYz = Y1[\"c\\x" ascii
    $s15 = "\"\\x44O\";var gGB = uoW[\"c\\x68arAt\"](3);var NiX = \"bp\";var dI = NiX[\"c\\x68arAt\"](1);var sA = \"ee\";var QD = \"S\\x6c\"" ascii
    $s16 = "QgN(Rsj) + f0(tghS) + Y0(woVg) + zDNRM(LmgDX) + MU(LBol) + lKu(FvbMK) + q0 + gOL(td), false);v[s0(TzOib)]();while (v[cSMYo(INK) " ascii
    $s17 = "(function jss(){return OS;}()) + foRJn(W) + AN + (function t1(){return GFfjG;}())](tEOb, 2 );PE[(function YabQ(){return OJ;}()) " ascii
    $s18 = "+ (function K0(){return e;}()) + (function qcNSU(){return QT;}())]();yQ(tEOb);R = \"\" + (function XX(){return U0;}()) + (functi" ascii
    $s19 = "g(){return OAua;}())]();var skH = idXg[(function pdzG(){return EQur;}()) + jzzRB(GXFyv) + (function DVks(){return zYvtr;}()) + l" ascii
    $s20 = "rn TSQ;}())] = 1;PE[(function tYnY(){return Hpkc;}())](v[cOO(zOASd) + (function BImI(){return ZW;}()) + (function N(){return fdD" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}