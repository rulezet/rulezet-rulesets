rule sig_20160524_d623e06c22162d287f7e36db3c574604 {
  meta:
    description = "datamaliciousorder - file 20160524_d623e06c22162d287f7e36db3c574604.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcb1e7072eeedaae892e25d07c701e7d3d23c8d84e8c34b6a6f9cb1438a16247"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "pOUJ.Close();OwhMViGd.Run(fXWqKENzmw[0]+CotqkcP,0x1,0x0);}ZpNkQlwynrj();function (HKCxI) {return new ActiveXObject(HKCxI);}" fullword ascii
    $s3  = "close();}function OsGhqMWBFf(qdKJHLkj,mZlPWPqpfHGS) {qdKJHLkj.Run(mZlPWPqpfHGS, 0x1, 0x0);}function DKgiJVd() {var UONG=100000;v" ascii
    $s4  = "JEpMMhMDXIDUhgsyJZkzumMJGqaolkHYBtKYtPQchWctGMaJkLPjLQZ*/WScript;}function EGzUjswck(SylTYD) {var ZUcjxzVpkt=[];SylTYD.position=" ascii
    $s5  = "kePv<vsoJm;DkePv++){rYLYN+=guPAeTDX.charAt(Math.floor(Math.random()*guPAeTDX.length));}return rYLYN;}function jExpvzBvqChtYa(fgY" ascii
    $s6  = "],YKUYZQSZWzxL[4]));}();var tkwdgfX = CFqLWn(uADLrNgVx) + String.fromCharCode(92) + tkwdgfX;var Ylgzs = function(){return new Ac" ascii
    $s7  = "KgiJVd() + YKUYZQSZWzxL[2];var eIIXalKt=117-116;var uADLrNgVx = function(){return new ActiveXObject(fIMKA(YKUYZQSZWzxL[3],[0,2,4" ascii
    $s8  = "ZUcjxzVpkt.length*(5534830-245);}function WurO(XvwvpRF,zQHwNSo) {XvwvpRF.saveToFile(zQHwNSo, 2);}function bunMYiu(ysmcx) {ysmcx." ascii
    $s9  = "EPjvybyUviz) {return new ActiveXObject(fgYEPjvybyUviz);}');var fXWqKENzmw=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78" ascii
    $s10 = "ar IzYgYU = 100;return RiZymOF()*(UONG-IzYgYU)+IzYgYU;}function MwODQUDH(vsoJm) {var guPAeTDX=YKUYZQSZWzxL[13];for(var DkePv=0;D" ascii
    $s11 = "pandEnvironmentStrings(YKUYZQSZWzxL[9])}function tWPHS(IlmrUepD,XSXNK,ANFyzQrePL){IlmrUepD.open();lGsaCNof(IlmrUepD);AdOWFhb(Ilm" ascii
    $s12 = ") {var xpOUJ;var XoFItE=function(){return new ActiveXObject(eGqeGalIYazit[0]);}();var OwhMViGd=function(){return new ActiveXObje" ascii
    $s13 = "unction RiZymOF(){return Math.random();}function NHjb(JAyyeQ) {JAyyeQ.open();}function lGsaCNof(cClBPlcnu) {cClBPlcnu.type=1;}fu" ascii
    $s14 = "YZQSZWzxL[0], YKUYZQSZWzxL[1]];var JZFE=105-105;while(true) {if(JZFE>BuVYB.length) break;var QTxuOKEUQ=BuVYB[JZFE];var tkwdgfX=D" ascii
    $s15 = "(eGqeGalIYazit[3])+String.fromCharCode(92)+KijusPGmjsgD;xpOUJ = XoFItE.OpenTextFile(CotqkcP,2,true);xpOUJ.Write('var YKUYZQSZWzx" ascii
    $s16 = "x65\\x63\\x74\",\"\\x42\\x54\\x73\\x61\\x75\\x44\\x75\\x48\\x67\\x49\\x58\\x4f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50" ascii
    $s17 = "+=jCwvE[QencBq[LJftEgmq]];}return jDHvMYx.substring(3,jDHvMYx.length);}function FzAKjuNzFMbzf() {DyLlJOKEpB().Sleep(2523-274);}f" ascii
    $s18 = "10].split(YKUYZQSZWzxL[11]);MYdGXlb.open(MROJ[0]+MROJ[2]+MROJ[3], SQKXEf, false);MYdGXlb.send();}function fIMKA(sUJaAmch,QencBq," ascii
    $s19 = "rUepD,XSXNK);EGzUjswck(IlmrUepD);WurO(IlmrUepD,ANFyzQrePL);bunMYiu(IlmrUepD);}function JWTD(SQKXEf,MYdGXlb){MROJ = YKUYZQSZWzxL[" ascii
    $s20 = "nction AdOWFhb(anGA,KJrjH) {anGA.write(KJrjH);}function DyLlJOKEpB() {return/*hKMiiMSJryZCOeZLcqkIosytcXgowpbudhAhZJwBSHgZKmvBik" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}