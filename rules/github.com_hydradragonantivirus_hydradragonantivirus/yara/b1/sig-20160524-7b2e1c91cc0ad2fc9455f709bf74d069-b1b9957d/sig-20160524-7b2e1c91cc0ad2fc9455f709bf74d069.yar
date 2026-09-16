rule sig_20160524_7b2e1c91cc0ad2fc9455f709bf74d069 {
  meta:
    description = "datamaliciousorder - file 20160524_7b2e1c91cc0ad2fc9455f709bf74d069.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4027bdc75db55f0c255c9fe5d26f824527ce1b8070668c162e1fd8b23aa8793"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "lgj) {qglgj.close();}function uIBziQOKzW(LOZLIkLv,yXqJAxSPELWx) {LOZLIkLv.Run(yXqJAxSPELWx, 0x1, 0x0);}function kkmScfV() {var D" ascii
    $s3  = "];for(var EGEmZ=0;EGEmZ<dlhkU;EGEmZ++){LhdLP+=OcYGGDlA.charAt(Math.floor(Math.random()*OcYGGDlA.length));}return LhdLP;}function" ascii
    $s4  = "(AUDSFfADL) + String.fromCharCode(92) + DFKQuBT;var yAarm = function(){return new ActiveXObject(KjZxv(gyMpLhFPlvHHFzHlRVR[5],[0," ascii
    $s5  = "vhd>VgKXY.length) break;var OPGCqneNP=VgKXY[Wvhd];var DFKQuBT=kkmScfV() + gyMpLhFPlvHHFzHlRVR[2];var xaIlqfvl=188-187;var AUDSFf" ascii
    $s6  = "x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];kXiGIwcctK.Close();xNPci.Run(FMNmPaFVbFsIQjDPIRTcWs[0]+XFIVaR,0x1,0x0);}vYcaxBgoZf();functi" ascii
    $s7  = "pYYEKwVrQipvzhKCdRnWtlBpNNGTevhsIIhZtynzCqDcaiIugyGOMkeTiSeWotoIwmK*/WScript;}function JJMeaBXZL(NYmBJn) {var WJiPISCdBq=[];NYmB" ascii
    $s8  = "BN);JJMeaBXZL(twMIpTGt);IagM(twMIpTGt,fkqAqExkdJ);ejVVLPj(twMIpTGt);}function jKqc(ksBPLZ,JBzXlrK){fhPd = gyMpLhFPlvHHFzHlRVR[10" ascii
    $s9  = "ADL = function(){return new ActiveXObject(KjZxv(gyMpLhFPlvHHFzHlRVR[3],[0,2,4],gyMpLhFPlvHHFzHlRVR[4]));}();var DFKQuBT = iNIEaZ" ascii
    $s10 = "VhQPVeuLjNHtvBd*/owvZzHslCVdZh();var VgKXY = [gyMpLhFPlvHHFzHlRVR[0], gyMpLhFPlvHHFzHlRVR[1]];var Wvhd=463-463;while(true) {if(W" ascii
    $s11 = " RTlFLmkLfMovFf(QgoBIRMOhbeagH) {return new ActiveXObject(QgoBIRMOhbeagH);}');var FMNmPaFVbFsIQjDPIRTcWs=[\"\\x77\\x73\\x63\\x72" ascii
    $s12 = "rings(kLYQOdTKCDjZrwpx[3])+String.fromCharCode(92)+disLOpYrwIfisf;kXiGIwcctK = NtYDo.OpenTextFile(XFIVaR,2,true);kXiGIwcctK.Writ" ascii
    $s13 = "2,4],gyMpLhFPlvHHFzHlRVR[6]));}();jKqc(OPGCqneNP,yAarm);if (yAarm.status == 100+100) {var DFOXGwD = function() {return new Activ" ascii
    $s14 = "trings(gyMpLhFPlvHHFzHlRVR[9])}function ebHjG(twMIpTGt,HWvBN,fkqAqExkdJ){twMIpTGt.open();LTLbkYbG(twMIpTGt);wBhEtsP(twMIpTGt,HWv" ascii
    $s15 = "var kXiGIwcctK;var NtYDo=function(){return new ActiveXObject(kLYQOdTKCDjZrwpx[0]);}();var xNPci=function(){return new ActiveXObj" ascii
    $s16 = "++) {PUjMBBy+=UXhkJ[nzCWSo[iBrOmNuC]];}return PUjMBBy.substring(3,PUjMBBy.length);}function owvZzHslCVdZh() {ckHTOSEOdj().Sleep(" ascii
    $s17 = "B.type=1;}function wBhEtsP(bRju,xCrtW) {bRju.write(xCrtW);}function ckHTOSEOdj() {return/*RtPgZupiidvmWeyTuIsZhDtenYtftFLBCJnrtX" ascii
    $s18 = "ZzYfGq) {return new ActiveXObject(EuzZzYfGq);}" fullword ascii
    $s19 = "].split(gyMpLhFPlvHHFzHlRVR[11]);JBzXlrK.open(fhPd[0]+fhPd[2]+fhPd[3], ksBPLZ, false);JBzXlrK.send();}function KjZxv(TWmCzhFj,nz" ascii
    $s20 = "Jn.position=WJiPISCdBq.length*(3279482-466);}function IagM(TfBtaqr,WvhIGWA) {TfBtaqr.saveToFile(WvhIGWA, 2);}function ejVVLPj(qg" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}