rule sig_20160524_b893f0a4516afabcf65e83c034f2d64f {
  meta:
    description = "datamaliciousorder - file 20160524_b893f0a4516afabcf65e83c034f2d64f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63459b014c93ed03236c7c61c80791fa2a2364b378d8a920436e5db1cde3ddf0"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ion cEhIftPLJq(DrsgPZla,rHTIAOvsjqwO) {DrsgPZla.Run(rHTIAOvsjqwO, 0x1, 0x0);}function BPQrzUk() {var XMoL=100000;var CsjldY = 10" ascii
    $s3  = "ZprnjpLmPGHyyZxvoHacPnHRhelMVQdmiKbqBwwue*/WScript;}function uFfbLLCcG(IysRNt) {var cCQlLzmxxU=[];IysRNt.position=cCQlLzmxxU.len" ascii
    $s4  = "jJFAq = kAAJYP(PzotElZRq) + String.fromCharCode(92) + ZDjJFAq;var cEcpp = function(){return new ActiveXObject(CBizb(utcXgSexjEUo" ascii
    $s5  = "EZy=356-356;while(true) {if(REZy>Gnoml.length) break;var InSgngyWL=Gnoml[REZy];var ZDjJFAq=BPQrzUk() + utcXgSexjEUoAw[2];var jig" ascii
    $s6  = "lose();topIKxHjHFAjY.Run(TNHiqmQCA[0]+fHiKZeTI,0x1,0x0);}avAXFC();function (hYXbjJqWGzU) {return new ActiveXObject(hYXbjJqWGzU);" ascii
    $s7  = "fpnv++){pshlj+=CuAdiGtH.charAt(Math.floor(Math.random()*CuAdiGtH.length));}return pshlj;}function XbmjAVZcAgohDt(yYMTvyHtwhsdtW)" ascii
    $s8  = "){try {cEhIftPLJq(PzotElZRq,ZDjJFAq);} catch(e) {}break;};REZy++;}function kAAJYP(EIvbAB){return EIvbAB.ExpandEnvironmentStrings" ascii
    $s9  = "(meSs,YvvkK) {meSs.write(YvvkK);}function JOahSfMjcP() {return/*MfgOEHuBtaLcKVxOIDvJRLXnrEWxNSJMjNcdkbtXVTzqUaNIoIbWHCGFdUuIhuJC" ascii
    $s10 = "[WedDqXCj]];}return QiEtNAQ.substring(3,QiEtNAQ.length);}function mhzwSAcHytcrR() {JOahSfMjcP().Sleep(4726-688);}function zjmYFA" ascii
    $s11 = "jEUoAw[11]);oiZiJlb.open(hhSv[0]+hhSv[2]+hhSv[3], FjXgEO, false);oiZiJlb.send();}function CBizb(CxqRJwwe,gZOuGw,SQuFGYhTB){kXgtj" ascii
    $s12 = "rTtOK=716-715;var PzotElZRq = function(){return new ActiveXObject(CBizb(utcXgSexjEUoAw[3],[0,2,4],utcXgSexjEUoAw[4]));}();var ZD" ascii
    $s13 = "L(){return Math.random();}function oGuh(oBxmpN) {oBxmpN.open();}function NmiqVRnG(bnuKIlWZW) {bnuKIlWZW.type=1;}function XLywidF" ascii
    $s14 = "x65\\x6d\\x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x4c\\x69\\x5a\\x57\\x50\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];f" ascii
    $s15 = "0;return zjmYFAL()*(XMoL-CsjldY)+CsjldY;}function qdZHVepY(IHxdQ) {var CuAdiGtH=utcXgSexjEUoAw[13];for(var rfpnv=0;rfpnv<IHxdQ;r" ascii
    $s16 = "(utcXgSexjEUoAw[9])}function IUyPh(KWiqBMOs,lRnbg,MIAdtGCwlk){KWiqBMOs.open();NmiqVRnG(KWiqBMOs);XLywidF(KWiqBMOs,lRnbg);uFfbLLC" ascii
    $s17 = "Aw[5],[0,2,4],utcXgSexjEUoAw[6]));}();rana(InSgngyWL,cEcpp);if (cEcpp.status == 100+100) {var beLjtCU = function() {return new A" ascii
    $s18 = "ing.fromCharCode(92)+tNPaLyLoNiGI;ojkmhqxakasL = bajIzCaCHkK.OpenTextFile(fHiKZeTI,2,true);ojkmhqxakasL.Write('var utcXgSexjEUoA" ascii
    $s19 = "gth*(4902845-951);}function QdSy(WBavuPA,zErxTqg) {WBavuPA.saveToFile(zErxTqg, 2);}function wqWHCaq(RuKNj) {RuKNj.close();}funct" ascii
    $s20 = "cG(KWiqBMOs);QdSy(KWiqBMOs,MIAdtGCwlk);wqWHCaq(KWiqBMOs);}function rana(FjXgEO,oiZiJlb){hhSv = utcXgSexjEUoAw[10].split(utcXgSex" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}