rule sig_20160321_f483dcec9dcf48e7241fb75792435821 {
  meta:
    description = "datamaliciousorder - file 20160321_f483dcec9dcf48e7241fb75792435821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faa99fe7d35243fdf99a87e4c50747e277be23b1124fd674fe68bf99cec9575b"

  strings:
    $s1  = "function Hxdj(DAvAf){return DAvAf;};var p1 = \"2\";var fV = p1[\"c\\x68\\x61rAt\"](0);var Cr = \"\\x368\\x31\\x36\";var aAouZ = " ascii
    $s2  = "= \"Creat\";var HsryD = function BNt() {return WScript[(function PvhVu(){return bIhLt;}()) + HzSVz + (function QgesP(){return Pn" ascii
    $s3  = " Tjrro + NHT(RwKc) + (function fI(){return wXsJ;}())]();WScript[(function ynumg(){return fe;}()) + Eit(SolF) + (function LNj(){r" ascii
    $s4  = "IEvd) + S0(K) + SOn(teDC)] < 4 ) {WScript[(function tET(){return fe;}()) + (function CPPe(){return SolF;}()) + hhkLB(g0) + (func" ascii
    $s5  = "sJ]();WScript[fe + (function UDDRQ(){return SolF;}()) + (function E(){return g0;}()) + Qw(H0)](bD());var ZY = new this[vG(nmWLa)" ascii
    $s6  = "(function Z(){return WPD;}())](wFT(wfP) + H1 + Dkv) + DU(Dnfg) + s0(R0) + ssiAg(DC) + rGuOo + bUn; Mf = G(); nqc = WScript[Jqz(b" ascii
    $s7  = " nb(){return PY;}());};function D(fdm, pvCN){return fdm - pvCN;};function QNNfh(){return p(bIhLt) + wPQt(HzSVz) + gWz(PndWg) + (" ascii
    $s8  = "GtXX = true;S = true;break;}}function chdK() {return EGtXX && S;};if (chdK()){LEfVY = HsryD[(function gf(){return ILfy;}()) + (f" ascii
    $s9  = "tion LKDap(){return H0;}())](bD() * 10)};lfXJI = false;} catch(e){};}XZk = WScript[QNNfh()]((function RJybL(){return xinF;}()) +" ascii
    $s10 = "K = \"M\\x69l\\x6c\";var A = vrAi[\"c\\x68\\x61rAt\"](5);var XMqd = \"g\\x65\";function Sa(I){return I;};function vG(SnvUG){retu" ascii
    $s11 = "D\";var xinF = \"AD\";var QVion = \"1ROSdN\";var ET = \"le\\x65p\";var bskF = QVion[\"c\\x68\\x61rAt\"](3);function E1(Wzx){retu" ascii
    $s12 = "function IS(CW){return CW;};var RL = \"QMfeJdyL\";var eq = RL[\"c\\x68\\x61rAt\"](3);var nmWLa = \"Dat\";var VR = \"s0dj2H\";var" ascii
    $s13 = "r kPF = \"KNaJT\";var AmaCD = kPF[\"c\\x68\\x61rAt\"](4);var ZNxv = \"\\x47E\";function nfFb(q){return q;};function f0(VJ){retur" ascii
    $s14 = "61\";var itwlq = \"\\x61s\\x64l\\x66\";function bA(fJ){return fJ;};var jMXw = \"T1eulD\";var MGVR = jMXw[\"c\\x68\\x61rAt\"](2);" ascii
    $s15 = "\";var rjiCY = \"ec\";var bkQk = VR[\"c\\x68\\x61rAt\"](3);var cQSH = \"\\x65\\x4f\\x62\";var ZdyM = \"\\x72\\x65at\";var kjX = " ascii
    $s16 = "DC = \"mB\\x77ZQ\";var R0 = \"\\x394\";var Dnfg = fZPTb[\"c\\x68\\x61rAt\"](3);function wFT(l){return l;};var lR = \"TSh9y%K8FCm" ascii
    $s17 = "Zf;};function hhkLB(E0){return E0;};var Uq = \"lO\";var H0 = \"e\\x70\";var g0 = \"\\x65\";var SolF = Uq[\"c\\x68\\x61rAt\"](0);" ascii
    $s18 = "66\";var JmK = eVPm[\"c\\x68\\x61rAt\"](1);var PC = \"asd\";function PDDut(BSrmc){return BSrmc;};function gFzc(ekP){return ekP;}" ascii
    $s19 = " \"\\x25/\";var H1 = \"T\\x45M\\x50\";var wfP = lR[\"c\\x68\\x61rAt\"](5);function NufH(xlW){return xlW;};function Dop(C0){retur" ascii
    $s20 = "unction wKJJH(TWMV){return TWMV;};var u = \"zbGsG\";var C = \"jec\\x74\";var PndWg = u[\"c\\x68\\x61rAt\"](1);var HzSVz = \"eO\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}