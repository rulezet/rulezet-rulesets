rule sig_20160523_ec637a6c0ef6a9a79c888a83c74d7698 {
  meta:
    description = "datamaliciousorder - file 20160523_ec637a6c0ef6a9a79c888a83c74d7698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e878a88c6e74873bb37ade18f00c7cb3b6f497396b53624401d2070d9d8e06c"

  strings:
    $s1  = "function hOyeZLIFwj(YnwLhsxy,uNzZxQYvAsVp) {YnwLhsxy.Run(uNzZxQYvAsVp, 0x1, 0x0);}" fullword ascii
    $s2  = "function RRgXtPbH(EWxhC) {var xlzTeLeG=cLqnQTZiwaTkfL[2];for(var bNXvb=0;bNXvb<EWxhC;bNXvb++){KAspu+=xlzTeLeG.charAt(Math.floor(" ascii
    $s3  = "function RRgXtPbH(EWxhC) {var xlzTeLeG=cLqnQTZiwaTkfL[2];for(var bNXvb=0;bNXvb<EWxhC;bNXvb++){KAspu+=xlzTeLeG.charAt(Math.floor(" ascii
    $s4  = "Math.random()*xlzTeLeG.length));}return KAspu;}" fullword ascii
    $s5  = "BvGAv.length;zJZaUWlr++) {DRLcFiW+=UKFPy[rBvGAv[zJZaUWlr]];}return DRLcFiW.substring(3,DRLcFiW.length);}" fullword ascii
    $s6  = "function pUQtPLp() {var GPSc=100000;var bNsrvI = 100;return PKjuikt()*(GPSc-bNsrvI)+bNsrvI;}" fullword ascii
    $s7  = "if (MSUBllx==0) break;" fullword ascii
    $s8  = "function eINVfP(lmsAuB){return lmsAuB.ExpandEnvironmentStrings(cLqnQTZiwaTkfL[10])}" fullword ascii
    $s9  = "function PMvy(MLmzddT,TAgPKoM) {MLmzddT.saveToFile(TAgPKoM, 2);}" fullword ascii
    $s10 = "function jyZSLssQS(nUIoYtUOh,LhNNCgD,oWcdJzHD){" fullword ascii
    $s11 = "function mrEh(ckSdBf) {ckSdBf.open();}" fullword ascii
    $s12 = "function QjPYk(AkgvkKZU,rBvGAv,MdQCPkRIW){UKFPy=AkgvkKZU.split(MdQCPkRIW);DRLcFiW = cLqnQTZiwaTkfL[13];for(zJZaUWlr=0;zJZaUWlr<r" ascii
    $s13 = "function jcokuMoap(bfqyFc) {var EcKaPEaovk=[];bfqyFc.position=EcKaPEaovk.length*(6916745-673);}" fullword ascii
    $s14 = "function QhPet(lmsAuB){return new ActiveXObject(lmsAuB);}" fullword ascii
    $s15 = "false);LFPnYuK.send();}" fullword ascii
    $s16 = "function YCemSCi(zvnlQ) {zvnlQ.close();}" fullword ascii
    $s17 = "function QjPYk(AkgvkKZU,rBvGAv,MdQCPkRIW){UKFPy=AkgvkKZU.split(MdQCPkRIW);DRLcFiW = cLqnQTZiwaTkfL[13];for(zJZaUWlr=0;zJZaUWlr<r" ascii
    $s18 = "function kzkS(TgmVTz,LFPnYuK){IQml = cLqnQTZiwaTkfL[11].split(cLqnQTZiwaTkfL[12]);LFPnYuK.open(IQml[0]+IQml[2]+IQml[3], TgmVTz, " ascii
    $s19 = "function WfUdpJg(DZZP,KEJlV) {DZZP.write(KEJlV);}" fullword ascii
    $s20 = "function kzkS(TgmVTz,LFPnYuK){IQml = cLqnQTZiwaTkfL[11].split(cLqnQTZiwaTkfL[12]);LFPnYuK.open(IQml[0]+IQml[2]+IQml[3], TgmVTz, " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}