rule sig_20160524_42e762d8faf7a73587c500b37f273951 {
  meta:
    description = "datamaliciousorder - file 20160524_42e762d8faf7a73587c500b37f273951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5adee8f76b740714c18b508c6b44f424976a4b76b4f620b7ba32484ddfdc1a81"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "KNBrhttuqDUU=function(){return new ActiveXObject(CMdeEfgLxDw[0]);}();var dJPiyDUCLc=function(){return new ActiveXObject(\"WScrip" ascii
    $s3  = "dHiQyN,lDFZCdwXSHvM) {hXdHiQyN.Run(lDFZCdwXSHvM, 0x1, 0x0);}function HhpWcSe() {var bHjG=100000;var twMIpT = 100;return tlBpNNG(" ascii
    $s4  = "kLARNJuAYQQbWrFsmXfYaVhQ*/WScript;}function ZzHslCVdZ(hDYtzy) {var eZrXRWTTkO=[];hDYtzy.position=eZrXRWTTkO.length*(1148024-511)" ascii
    $s5  = "arAt(Math.floor(Math.random()*xkdJjKqc.length));}return ZJBzX;}function fFqbyQIHsqpvjj(xjYcRohYICJCJr) {return new ActiveXObject" ascii
    $s6  = " break;var xGjcoPJYP=EaZdm[MeaB];var KjZxvTW=HhpWcSe() + uXukc[2];var mCzhFjnz=301-300;var CWSoASCsz = function(){return new Act" ascii
    $s7  = "P);ZzHslCVdZ(WvhIGWAe);RCJH(WvhIGWAe,jqglgjuIBz);szeEQpI(WvhIGWAe);}function iQOK(zWLOZL,IkLvyXq){JAxS = uXukc[10].split(uXukc[1" ascii
    $s8  = " function(){return new ActiveXObject(iidvm(uXukc[5],[0,2,4],uXukc[6]));}();iQOK(xGjcoPJYP,uCUXh);if (uCUXh.status == 100+100) {v" ascii
    $s9  = "OTefjfpDsDLnaGPnsezigrneCk*/PVeuLjNHtvBdR();var EaZdm = [uXukc[0], uXukc[1]];var MeaB=909-909;while(true) {if(MeaB>EaZdm.length)" ascii
    $s10 = "ar kJPUjMB = function() {return new ActiveXObject(iidvm(uXukc[7],[0,2,4],uXukc[8]));}();Btaqr(kJPUjMB,uCUXh.ResponseBody,KjZxvTW" ascii
    $s11 = "])+String.fromCharCode(92)+edMeLKiUVmBe;JhJpQGj = lQKNBrhttuqDUU.OpenTextFile(jQWwCK,2,true);JhJpQGj.Write('var uXukc=[\"\\x68" ascii
    $s12 = "1]);IkLvyXq.open(JAxS[0]+JAxS[2]+JAxS[3], zWLOZL, false);IkLvyXq.send();}function iidvm(WeyTuIsZ,hDtenY,tftFLBCJn){wVrQi=WeyTuIs" ascii
    $s13 = "x6a\\x65\\x63\\x74\",\"\\x72\\x6a\\x44\\x45\\x6b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function GdRZkGjRVHwA" ascii
    $s14 = "rn pvzhKCd.substring(3,pvzhKCd.length);}function PVeuLjNHtvBdR() {tiAWPWkGtR().Sleep(3636-240);}function tlBpNNG(){return Math.r" ascii
    $s15 = "w.write(mKowv);}function tiAWPWkGtR() {return/*xwPjLvpRakEhMSUWWZWDaKWSYDEjnJhtTIpOnDplubQeNffipvURzctXpEnQkgPpjnKMJfiZIlWuHLkOB" ascii
    $s16 = "un(YSNLXevsHtGKtHYWPavGS[0]+jQWwCK,0x1,0x0);}GdRZkGjRVHwAWt();function (QDxzxlwgJxdB) {return new ActiveXObject(QDxzxlwgJxdB);}" fullword ascii
    $s17 = ")*(bHjG-twMIpT)+twMIpT;}function GtHWvBNf(kqAqE) {var xkdJjKqc=uXukc[13];for(var ksBPL=0;ksBPL<kqAqE;ksBPL++){ZJBzX+=xkdJjKqc.ch" ascii
    $s18 = ";}function RCJH(wSleufo,mVjRJMt) {wSleufo.saveToFile(mVjRJMt, 2);}function szeEQpI(fJhJQ) {fJhJQ.close();}function VITcaXxHUD(hX" ascii
    $s19 = "andom();}function Tevh(sIIhZt) {sIIhZt.open();}function ynzCqDca(iIugyGOMk) {iIugyGOMk.type=1;}function eTiSeWo(toIw,mKowv) {toI" ascii
    $s20 = ");}if (mCzhFjnz > 0){try {VITcaXxHUD(CWSoASCsz,KjZxvTW);} catch(e) {}break;};MeaB++;}function iPISCd(mBJnWJ){return mBJnWJ.Expan" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}