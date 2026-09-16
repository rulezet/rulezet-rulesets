rule sig_20160321_7c93e340b6ce162cfea1e86cb9e024c8 {
  meta:
    description = "datamaliciousorder - file 20160321_7c93e340b6ce162cfea1e86cb9e024c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a29bc3bd3c0b111f31c14fd4971afabce2a8644c5ee3021be3ad18e138da2c56"

  strings:
    $s1  = "function NF(cyO){return cyO;};var UA = \"\\x31\\x362\";var Lvuc = \"368\";var b1 = \"218\";var UdWnF = \"sdf\";var Z = \"\\x61sd" ascii
    $s2  = "r TShI = \"Cr\\x65\";var g = function qjzfe() {return WScript[(function S(){return TShI;}()) + gQ + (function gAs(){return ioO;}" ascii
    $s3  = "G) + (function y0(){return wP;}())]();var UkdUW = q[(function eZ(){return dvu;}()) + UtDG + l(oM) + Gadj + YMlj(LM)]();WScript[(" ascii
    $s4  = ") + (function acoko(){return NUQ;}()) + (function tT(){return D;}())] < 4 ) {WScript[JeBLw(TCLKU) + (function QCX(){return RAMgd" ascii
    $s5  = "urn KWd;}()) + mpGnw(yJ); XC = BnViY(); nA = WScript[e(TShI) + gQ + ioO + y(TZo) + rno(HCEeE)](XC); var xMGk = true; while (xMGk" ascii
    $s6  = " LM;}())]();WScript[TCLKU + (function UCIg(){return RAMgd;}()) + (function BEUa(){return mYSk;}())](Ok());var q = new this[C0(Q0" ascii
    $s7  = "(d);};function BskO(b, rs){return b - rs;};function r(){return (function WpEb(){return TShI;}()) + O(gQ) + (function rx(){return" ascii
    $s8  = " Ok() * 1; KkVgh++){if (ip() != 0){DXvYT = true;t = true;break;}}function YPnxF() {return DXvYT && t;};if (YPnxF()){oCjkk = g[rd" ascii
    $s9  = ";}()) + OVX(mYSk)](Ok() * 10)};xMGk = false;} catch(e){};}AaKSd = WScript[r()](IioZk(cmXlo) + (function kQV(){return Yhf;}()) + " ascii
    $s10 = "turn tKoG;};var eL = \"feNv\";var z = \"d8JPpcyuNP\";var mYSk = z[\"c\\x68arAt\"](4);var RAMgd = eL[\"c\\x68arAt\"](1);var TCLKU" ascii
    $s11 = "on rno(iPu){return iPu;};var W = \"J79TeY28\";var HCEeE = \"ct\";var TZo = W[\"c\\x68arAt\"](4);var ioO = \"\\x6a\";var gQ = \"a" ascii
    $s12 = "D = \"tat\\x65\";var NUQ = E[\"c\\x68arAt\"](2);var NqHzC = \"\\x72eady\";function Yjg(qhhXC){return qhhXC;};var WclZp = \"sen" ascii
    $s13 = ";function XVVii(qQcp){return qQcp;};var c = \"MLiqvlp\";var LM = \"onds\";var Gadj = \"\\x73ec\";var oM = c[\"c\\x68arAt\"](2);v" ascii
    $s14 = " = \"MLH\";var O0 = \"\\x4c2.X\";var ZFNCp = \"SXM\";var qJ = Sjoq[\"c\\x68arAt\"](2);var vW = \"\\x52\\x75n\";function v(efd){r" ascii
    $s15 = "Ew = \"pen\";var Ymxg = F0[\"c\\x68arAt\"](5);function IioZk(rBh){return rBh;};function iFKC(mo){return mo;};var GWNE = \"m6hvt" ascii
    $s16 = " vLypm(yMq){return yMq;};var qpXs = \"aA30ze7Yc2\";var Cj = qpXs[\"c\\x68arAt\"](5);var PD = \"\\x74\\x79p\";var F0 = \"RmGipozH" ascii
    $s17 = "UZyT\";var hywHK = \"Gd\";var it = V0[\"c\\x68arAt\"](0);function PW(mFT){return mFT;};var RIlTB = \"M\\x50%/\";var uBp = \"%\\x" ascii
    $s18 = "rBc + SrCk(wuw) + lqOw + (function S0(){return nUy;}()) + VQNp + aKtK(MXyuQ) + b0 + (function Gj(){return iYKWh;}()) + (function" ascii
    $s19 = "ZfI + LN + (function XVmK(){return VkOJ;}()) + lLk(o) + dkxC + dkaU + (function L(){return nb;}()) + OGW(T) + (function WR(){ret" ascii
    $s20 = "PD + vLypm(Cj)] = 1;AaKSd[Th(WE) + (function QirU(){return BAY;}()) + QCl(Nam)](nA[dZjph(SOVu) + (function oKLf(){return N0;}())" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}