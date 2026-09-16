rule sig_20160321_8d71845575d921970b9a0cb89c57bd8b {
  meta:
    description = "datamaliciousorder - file 20160321_8d71845575d921970b9a0cb89c57bd8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "256d84a4ff855f6cc2695c3e394994b83aab37e3160f789fc8866864579be80d"

  strings:
    $s1  = "function G0(eWtk){return eWtk;};var MDpYu = \"tq9Vq8QfuM\";var xF = \"2\";var vrsCP = \"16\";var GBKgo = MDpYu[\"ch\\x61rAt\"](5" ascii
    $s2  = "\\x70\";var sjEd = CJOOG[\"ch\\x61rAt\"](0);var f = \"\\x3a\\x2f\\x2f\";var K0 = \"p\";var t0 = \"h\\x74t\";var TvFq = \"GET\";f" ascii
    $s3  = "{return wjc;}()) + rp(Z0) + eRGxx; BBG = jr(); wyN = WScript[(function CE(){return KZ;}()) + hRg(Fi) + gm + lHBw + aVly](BBG); v" ascii
    $s4  = "f = function OM() {return WScript[fL(KZ) + (function MWbx(){return Fi;}()) + (function KXT(){return gm;}()) + BB(lHBw) + (functi" ascii
    $s5  = " sxq(uNPAA) + (function AmV(){return HxneA;}())]();WScript[(function xYom(){return kqGj;}()) + Ki(RjVr)](ZrUMH());var L = new th" ascii
    $s6  = "function bpodb(){return o2;}()), false);wyN[XZY(Bk) + FyM]();while (wyN[NID(P0) + we] < 4 ) {WScript[(function jbTZL(){return kq" ascii
    $s7  = "(function uOgmq(){return uNPAA;}()) + (function nA(){return HxneA;}())]();WScript[kqGj + (function t(){return RjVr;}())](ZrUMH()" ascii
    $s8  = " XI){return y - XI;};function yre(){return KZ + ANiQ(Fi) + cGN(gm) + pf(lHBw) + (function lse(){return aVly;}());};function ZrUM" ascii
    $s9  = "++){if (o() != 0){NlAF = true;bDDro = true;break;}}function xZC() {return NlAF && bDDro;};if (xZC()){J = oMCf[r(lr) + (function " ascii
    $s10 = "FSC;}()) + Pmoa + (function Coq(){return gReR;}()) + dJt(oYNYq) + (function lFnnk(){return P1;}()) + (function p(){return oOOl;}" ascii
    $s11 = "Gj;}()) + (function QN(){return RjVr;}())](ZrUMH() * 10)};Z = false;} catch(e){};}kRs = WScript[yre()]((function om(){return j;}" ascii
    $s12 = "aQ){return AJAaQ;};var QR = \"\\x6e\";var cUBV = \"p\\x65\";var gG = \"o\";var KL = \"gztc\";var ub = KL[\"ch\\x61rAt\"](2);var " ascii
    $s13 = "UlU\";var rkR = \"f\";var YkCF = \"sd\";var M1 = \"sd\\x66\\x61\";var R1 = eWTDm[\"ch\\x61rAt\"](2);function vdyz(PMI){return PM" ascii
    $s14 = "OAQ = \"bje\";var M = \"t\\x65O\";var PAmuz = \"r\\x65a\";var sMbq = sILZq[\"ch\\x61rAt\"](2);function GjFE(A){return A;};var im" ascii
    $s15 = "return RAt;};var HxneA = \"ds\";var uNPAA = \"\\x6e\";var W1 = \"\\x65c\\x6f\";var Yhk = \"llis\";var KtpYm = \"\\x67\\x65tMi\";" ascii
    $s16 = "= \"espon\";var ONEEi = h[\"ch\\x61rAt\"](4);function ozff(PAb){return PAb;};var vaOR = \"epNMiZ\";var u0 = vaOR[\"ch\\x61rAt\"]" ascii
    $s17 = "function G0(eWtk){return eWtk;};var MDpYu = \"tq9Vq8QfuM\";var xF = \"2\";var vrsCP = \"16\";var GBKgo = MDpYu[\"ch\\x61rAt\"](5" ascii
    $s18 = ";var RjVr = \"\\x65\\x70\";var kqGj = \"Sle\";function JQdH(CpmqT){return CpmqT;};function aDkP(xQPf){return xQPf;};function sxq" ascii
    $s19 = "){return W0;};var S = \"e\";var nrHk = \"Dat\";var sILZq = \"5FC5\";var z = \"gmSt922oW\";var dYU = z[\"ch\\x61rAt\"](3);var zX " ascii
    $s20 = "c\";var i = \"lli\";var otKVY = \"\\x69\";var M0 = \"getM\";var Oa = \"e\";var aDT = \"at\";var KjTXK = \"\\x44\";function Ki(UW" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}