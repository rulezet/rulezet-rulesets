rule sig_20160321_1fca38acc3a83f22859e7a7b60c792ab {
  meta:
    description = "datamaliciousorder - file 20160321_1fca38acc3a83f22859e7a7b60c792ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a3e0f58ac4f2b46199f38272da949b10918eb608c1b697078103b34a73208f"

  strings:
    $s1  = "function bowXL(TKm){return TKm;};var LA = \"2\";var E1 = \"816\";var tNOc = \"2183\\x36\";function na(zkKB){return zkKB;};functi" ascii
    $s2  = " new this[ptgIG]();var KZL = RnaX[ksq + MjZI(sN) + (function HPgc(){return WmyKM;}()) + t0 + sD(ZZb)]();WScript[(function XCFs()" ascii
    $s3  = "\";var No = function NL() {return WScript[kFbQ + RBTsI(cME) + Mnb(olPEO) + (function cCLk(){return DtR;}())](s0(Vm) + p(SzknW) +" ascii
    $s4  = ") + WmyKM + M0(t0) + zs(ZZb)]();WScript[(function Ms(){return wfiMh;}()) + (function abYYe(){return i0;}())](wtQRj());var RnaX =" ascii
    $s5  = "+ JO(Z); MgSfG = V(); mOM = WScript[(function s(){return kFbQ;}()) + E(cME) + zl(olPEO) + cVD(DtR)](MgSfG); var EThpR = true; wh" ascii
    $s6  = "h(e){};}S = WScript[cfEI()](FYm(x) + oepS(Qonif) + (function mmgI(){return ymM;}()));S[((function h(){return QCB;}()) + (functio" ascii
    $s7  = "+ (function R0(){return Lep;}()) + (function lRw(){return A;}());};function eoZK(BzW, BJCcZ){return BzW - BJCcZ;};function cfEI(" ascii
    $s8  = "() {return GH && yZMSH;};if (sUy()){xLlQ = No[(function is(){return snbNm;}()) + D(Aj) + cdGX + (function gCm(){return FiYXz;}()" ascii
    $s9  = "+ (function BRlp(){return yCTta;}())] < 4 ) {WScript[(function XiA(){return wfiMh;}()) + i0](wtQRj() * 10)};EThpR = false;} catc" ascii
    $s10 = "var x = \"AD\\x4f\\x44\";var gnES = \"kDQeoSb\";var ZgpMS = \"\\x6ceep\";var zu = gnES[\"c\\x68arAt\"](5);function pn0(siULO){re" ascii
    $s11 = "\"vNp\";var i0 = q[\"c\\x68arAt\"](2);var wfiMh = \"Sl\\x65e\";function v(Er){return Er;};function M0(xMNo){return xMNo;};functi" ascii
    $s12 = "et\";var ksq = i[\"c\\x68arAt\"](4);function cfvhN(lciO){return lciO;};var ptgIG = \"\\x44ate\";var k = \"dcbc\";var s1 = \"\\x7" ascii
    $s13 = "arAt\"](5);var sKG = \"bz6b\\x30\";var Hs = \"Xx\";function cFPbf(YCCD){return YCCD;};var WAlIz = \"\\x4d\\x50%/\";var RdfQ = \"" ascii
    $s14 = "ar LmyuL = \"hel\\x6c\";var rOnuX = \".\\x53\";var iqjwD = \"r\\x69\\x70t\";var SzknW = pn[\"c\\x68arAt\"](5);var Vm = \"WS\";fu" ascii
    $s15 = "= k[\"c\\x68arAt\"](3);var yUeVd = \"bj\\x65\";var DzrjK = \"eO\";var O0 = \"C\\x72ea\\x74\";function M(qL){return qL;};var t = " ascii
    $s16 = "c\\x6f\";var uiEq = \"l\";var snoj = \"Mil\";var tCE = \"get\";var shxD = \"e\";var R1 = \"D\\x61t\";function rV(xvJA){return xv" ascii
    $s17 = "GH = false;var yZMSH = false;for (var Kk = 0; Kk < wtQRj() * 1; Kk++){if (rf() != 0){GH = true;yZMSH = true;break;}}function sUy" ascii
    $s18 = "n hFT(){return rhTP;}()))]();S[(function lazas(){return W;}())] = 1;S[JxUs + (function wu(){return YdhZI;}()) + (function ldK(){" ascii
    $s19 = "){return (function hEuD(){return kFbQ;}()) + (function C(){return cME;}()) + PeA(olPEO) + (function Fwpj(){return DtR;}());};fun" ascii
    $s20 = "{return wfiMh;}()) + rV(i0)](wtQRj());var RnaX = new this[ptgIG]();var chbFO = RnaX[li(ksq) + sN + GLf(WmyKM) + (function XaT(){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}