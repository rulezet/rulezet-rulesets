rule sig_20160524_c68e207930961ad7f2260f595d98eca7 {
  meta:
    description = "datamaliciousorder - file 20160524_c68e207930961ad7f2260f595d98eca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d451b5f02434b56245c78f5fab70a73eba7b45af347ffef8fe7b55fd8361aba"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "tion(){return new ActiveXObject(\"WScript.Shell\");}();var KeJbc = HUVOrEjBvSqKYkJVkBEgS[1]+12113+HUVOrEjBvSqKYkJVkBEgS[2];var F" ascii
    $s3  = "fwLxpLRACV) {BIxHpTlJ.Run(TxfwLxpLRACV, 0x1, 0x0);}function wLxKwFZ() {var SbKq=100000;var XxRuFv = 100;return fDuzxTu()*(SbKq-X" ascii
    $s4  = "dNrVlNQdCgXuvqSe*/WScript;}function wZomaBHbx(uSxfbb) {var JQvLxVadam=[];uSxfbb.position=JQvLxVadam.length*(961639-971);}functio" ascii
    $s5  = "xRuFv)+XxRuFv;}function tJThhiss(Apjop) {var cUFSUGEb=TxjKKN[13];for(var PYVim=0;PYVim<Apjop;PYVim++){ZQfip+=cUFSUGEb.charAt(Mat" ascii
    $s6  = "xjKKN[3],[0,2,4],TxjKKN[4]));}();var MQtAtqz = VyOXfz(NErcDmvGA) + String.fromCharCode(92) + MQtAtqz;var QSXxs = function(){retu" ascii
    $s7  = "d=rrLlu[SxGD];var MQtAtqz=wLxKwFZ() + TxjKKN[2];var kMBqUkTY=736-735;var NErcDmvGA = function(){return new ActiveXObject(yoFun(T" ascii
    $s8  = "Strings(TxjKKN[9])}function UflQx(MMxeBenI,wRaAW,fUxZyGTebw){MMxeBenI.open();NMBGwNxE(MMxeBenI);vaVlYaQ(MMxeBenI,wRaAW);wZomaBHb" ascii
    $s9  = "QWHP,2,true);rLQnz.Write('var TxjKKN=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70\\x2e\\x64\\x65\\x6c\\x69\\x63\\x" ascii
    $s10 = "];function vDUbFlOFO() {var rLQnz;var JsnwUi=function(){return new ActiveXObject(HUVOrEjBvSqKYkJVkBEgS[0]);}();var gDnZbgkX=func" ascii
    $s11 = "WJQWHP,0x1,0x0);}vDUbFlOFO();function (WXNqcw) {return new ActiveXObject(WXNqcw);}" fullword ascii
    $s12 = "qT.open(uYpn[0]+uYpn[2]+uYpn[3], XMEIQL, false);obzGCqT.send();}function yoFun(xlzytXEq,WLpBwc,KqNStulGx){duWtA=xlzytXEq.split(K" ascii
    $s13 = "qNStulGx);UnUsMvO = TxjKKN[12];for(YIrzPxxF=0;YIrzPxxF<WLpBwc.length;YIrzPxxF++) {UnUsMvO+=duWtA[WLpBwc[YIrzPxxF]];}return UnUsM" ascii
    $s14 = "unction() {return new ActiveXObject(yoFun(TxjKKN[7],[0,2,4],TxjKKN[8]));}();UflQx(CFasYfy,QSXxs.ResponseBody,MQtAtqz);}if (kMBqU" ascii
    $s15 = "vO.substring(3,UnUsMvO.length);}function GrfVDGQccjCmw() {IJdSiEDSQp().Sleep(4426-958);}function fDuzxTu(){return Math.random();" ascii
    $s16 = "eUOiq);}function IJdSiEDSQp() {return/*nQFwTbZdGsWPmhUMWmSxvYpcVkighoWNqaDDiODGVvSBnmWtwgNOhvPPGXbbEcUFnEvdrVaCdRIHhLRvPuByNmjVl" ascii
    $s17 = "x(MMxeBenI);PGbi(MMxeBenI,fUxZyGTebw);RewCCEJ(MMxeBenI);}function Ejsc(XMEIQL,obzGCqT){uYpn = TxjKKN[10].split(TxjKKN[11]);obzGC" ascii
    $s18 = "n PGbi(nzNBqoV,HydJtKy) {nzNBqoV.saveToFile(HydJtKy, 2);}function RewCCEJ(WDlUJ) {WDlUJ.close();}function fScvSRFkdY(BIxHpTlJ,Tx" ascii
    $s19 = "TKRkQ*/GrfVDGQccjCmw();var rrLlu = [TxjKKN[0], TxjKKN[1]];var SxGD=581-581;while(true) {if(SxGD>rrLlu.length) break;var FRyxJabu" ascii
    $s20 = "}function TXxh(XiaYjj) {XiaYjj.open();}function NMBGwNxE(nVXGWAzTJ) {nVXGWAzTJ.type=1;}function vaVlYaQ(Oawk,eUOiq) {Oawk.write(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}