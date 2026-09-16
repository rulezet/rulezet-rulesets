rule sig_20160523_6b3955cb695517153c374f9a979e6db0 {
  meta:
    description = "datamaliciousorder - file 20160523_6b3955cb695517153c374f9a979e6db0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72f0a8ed40f7be3dc07a86593a3fd210bc60fb2a5aec5c947fe31c9131dc1f58"

  strings:
    $s1  = "function bvDJmBznOU(oKHfKsoo,WdIYKinqnzcT) {oKHfKsoo.Run(WdIYKinqnzcT, 0x1, 0x0);}" fullword ascii
    $s2  = "function iDDygBNA(Aulgu) {var uQqtnSBD=nvIJHMROOBiEvvL[2];for(var kkMBW=0;kkMBW<Aulgu;kkMBW++){jwtJI+=uQqtnSBD.charAt(Math.floor" ascii
    $s3  = "function iDDygBNA(Aulgu) {var uQqtnSBD=nvIJHMROOBiEvvL[2];for(var kkMBW=0;kkMBW<Aulgu;kkMBW++){jwtJI+=uQqtnSBD.charAt(Math.floor" ascii
    $s4  = "function LBSH(AKyMLG) {AKyMLG.open();}" fullword ascii
    $s5  = "function kRDjYCOJ(pXDafGHyT) {pXDafGHyT.type=1;}" fullword ascii
    $s6  = "function yfKT(QZpCmr,eFrRtzi){Lbks = nvIJHMROOBiEvvL[11].split(nvIJHMROOBiEvvL[12]);eFrRtzi.open(Lbks[0]+Lbks[2]+Lbks[3], QZpCmr" ascii
    $s7  = "function KlVEMcK(KSqH,jGNhA) {KSqH.write(jGNhA);}" fullword ascii
    $s8  = ", false);eFrRtzi.send();}" fullword ascii
    $s9  = "function cWGML(WCQKOe){return new ActiveXObject(WCQKOe);}" fullword ascii
    $s10 = "(Math.random()*uQqtnSBD.length));}return jwtJI;}" fullword ascii
    $s11 = "function HzEGPRx(){return Math.random();}" fullword ascii
    $s12 = "function eyDwvZ(WCQKOe){return WCQKOe.ExpandEnvironmentStrings(nvIJHMROOBiEvvL[10])}" fullword ascii
    $s13 = "function niylndb(nJxrh) {nJxrh.close();}" fullword ascii
    $s14 = "function aZOT(JaKRAik,TjNMgWI) {JaKRAik.saveToFile(TjNMgWI, 2);}" fullword ascii
    $s15 = "function yfKT(QZpCmr,eFrRtzi){Lbks = nvIJHMROOBiEvvL[11].split(nvIJHMROOBiEvvL[12]);eFrRtzi.open(Lbks[0]+Lbks[2]+Lbks[3], QZpCmr" ascii
    $s16 = "function DEEYyHJYK(DkKeHSIGW,guuvFFN,CwBCphSf){" fullword ascii
    $s17 = "function nbggtoD() {var JLEd=100000;var gPaRpC = 100;return HzEGPRx()*(JLEd-gPaRpC)+gPaRpC;}" fullword ascii
    $s18 = "if (XJSmfoX==0) break;" fullword ascii
    $s19 = "function hFZIbCBes(QHMKgH) {var gkKukvnlww=[];QHMKgH.position=gkKukvnlww.length*(2116876-263);}" fullword ascii
    $s20 = "function biHkB(aGuXptIs,kMaty,cUeqjnexxE){LBSH(aGuXptIs);kRDjYCOJ(aGuXptIs);KlVEMcK(aGuXptIs,kMaty);hFZIbCBes(aGuXptIs);aZOT(aGu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}