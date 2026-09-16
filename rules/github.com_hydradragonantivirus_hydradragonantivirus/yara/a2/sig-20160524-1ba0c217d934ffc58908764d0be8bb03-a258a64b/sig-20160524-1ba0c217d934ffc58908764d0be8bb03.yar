rule sig_20160524_1ba0c217d934ffc58908764d0be8bb03 {
  meta:
    description = "datamaliciousorder - file 20160524_1ba0c217d934ffc58908764d0be8bb03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc80e7ba9329bc5aa3365e7aa0ae697677e93386854c9bc1edf93f7189afe8f1"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "iveXObject(QjByt[0]);}();var EtMGXQtXKjCLd=function(){return new ActiveXObject(\"WScript.Shell\");}();var XDTufPSiRYnZTZ = QjByt" ascii
    $s3  = "FAqjigrTtOKPzotElZRqNNbDSVxyLqcEcppbeLjtCUhMHKjJfxMrhaPoyLQEpwOTtxhmUIUnFuycJzSiTpBMuIxsXVeeOV*/WScript;}function JBiuIMeFR(izvH" ascii
    $s4  = "q, 2);}function dZHVepY(IHxdQ) {IHxdQ.close();}function CuAdiGtHrf(pnvpshlj,gbflLeWuMeah) {pnvpshlj.Run(gbflLeWuMeah, 0x1, 0x0);" ascii
    $s5  = "mCPf=SrClAjV() + BQaCLTRvDdkNgQK[2];var TCsoYEeB=656-655;var tFGDwfbGY = function(){return new ActiveXObject(jWGHt(BQaCLTRvDdkNg" ascii
    $s6  = "QK[3],[0,2,4],BQaCLTRvDdkNgQK[4]));}();var gsOmCPf = VQNpVr(tFGDwfbGY) + String.fromCharCode(92) + gsOmCPf;var EzGST = function(" ascii
    $s7  = ",FLbFofs){zzUU = BQaCLTRvDdkNgQK[10].split(BQaCLTRvDdkNgQK[11]);FLbFofs.open(zzUU[0]+zzUU[2]+zzUU[3], HRNtxm, false);FLbFofs.sen" ascii
    $s8  = "\\x63\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function GjUbRzmC() {var UvKmjwmJoIZTk;var ftZmXrAVZP=function()" ascii
    $s9  = "WE) {var HeEgHGnoml=[];izvHWE.position=HeEgHGnoml.length*(280056-382);}function BPQr(zUkXMoL,CsjldYq) {zUkXMoL.saveToFile(CsjldY" ascii
    $s10 = "bpKWxIzT(BEFZXOkx);NDxaJQG(BEFZXOkx,iNxtn);JBiuIMeFR(BEFZXOkx);BPQr(BEFZXOkx,NjMRzMbYiZ);dZHVepY(BEFZXOkx);}function ioAm(HRNtxm" ascii
    $s11 = "bLbU<scnJSb.length;FWRnbLbU++) {BGBAYLy+=aNnEU[scnJSb[FWRnbLbU]];}return BGBAYLy.substring(3,BGBAYLy.length);}function uCEZTREZy" ascii
    $s12 = "){return new ActiveXObject(jWGHt(BQaCLTRvDdkNgQK[5],[0,2,4],BQaCLTRvDdkNgQK[6]));}();ioAm(gCTrxnvFK,EzGST);if (EzGST.status == 1" ascii
    $s13 = "KWxIzT(tyNCgjEiC) {tyNCgjEiC.type=1;}function NDxaJQG(qVVv,SWXaw) {qVVv.write(SWXaw);}function mllxSkUPIn() {return/*SgngyWLZDjJ" ascii
    $s14 = "CLTRvDdkNgQK[0], BQaCLTRvDdkNgQK[1]];var Hyix=221-221;while(true) {if(Hyix>OxIvg.length) break;var gCTrxnvFK=OxIvg[Hyix];var gsO" ascii
    $s15 = "00+100) {var wZEPDgm = function() {return new ActiveXObject(jWGHt(BQaCLTRvDdkNgQK[7],[0,2,4],BQaCLTRvDdkNgQK[8]));}();eoyqB(wZEP" ascii
    $s16 = "BAoI() {mllxSkUPIn().Sleep(5366-987);}function FSpWHNF(){return Math.random();}function NROz(JUnuPa) {JUnuPa.open();}function bp" ascii
    $s17 = "0x0);}GjUbRzmC();function (yFlCMWZsILVfLY) {return new ActiveXObject(yFlCMWZsILVfLY);}" fullword ascii
    $s18 = "d();}function jWGHt(gjfKogdb,scnJSb,VBKJLTveW){aNnEU=gjfKogdb.split(VBKJLTveW);BGBAYLy = BQaCLTRvDdkNgQK[12];for(FWRnbLbU=0;FWRn" ascii
    $s19 = "return VtBeS;}function IysRNtcCQlLzmx(xUQdSyWBavuPAz) {return new ActiveXObject(xUQdSyWBavuPAz);}');var tLrglatFajuFgvsKKMRZxk=[" ascii
    $s20 = " = ftZmXrAVZP.OpenTextFile(rlvNM,2,true);UvKmjwmJoIZTk.Write('var BQaCLTRvDdkNgQK=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}