rule sig_20160524_6799b4d583588a07ab0299fb0d7ce19a {
  meta:
    description = "datamaliciousorder - file 20160524_6799b4d583588a07ab0299fb0d7ce19a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5ac9a206994546e0bf6fd5c834d907a51b6d90c0f8fb08fceae57b1c1dc661a"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "veToFile(elbHzYr, 2);}function DrNRDzB(ftpOn) {ftpOn.close();}function jExVLLcflA(zytrpewb,vDeWpYDUWWFm) {zytrpewb.Run(vDeWpYDUW" ascii
    $s3  = "ctiveXObject(mdqfjv[0]);}();var owROhKgpbov=function(){return new ActiveXObject(\"WScript.Shell\");}();var aKnBQa = mdqfjv[1]+17" ascii
    $s4  = "n/*HFRzcYmBeXKiyVKAxIkgKCIgzwdfzITiXccTEYdrFnUhMnZvkPsKKmvgxwjokJemhUgGasNAaWWATYiJQqtHCpczpOiQOfkLkeeNqfqdp*/WScript;}function " ascii
    $s5  = ";}();var VVPCKxq = gJhyly(itDfMjIeY) + String.fromCharCode(92) + VVPCKxq;var AiARx = function(){return new ActiveXObject(eVObi(U" ascii
    $s6  = "2;while(true) {if(Wjbd>MYNJK.length) break;var QjaDIBEVr=MYNJK[Wjbd];var VVPCKxq=SWXvgyb() + UAuoFEHIItxuLrVftlfTx[2];var BLjdZr" ascii
    $s7  = "aCyyxoyoM.OpenTextFile(KWzRDNLFknIR,2,true);wMIKcQYetwaG.Write('var UAuoFEHIItxuLrVftlfTx=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f" ascii
    $s8  = "DXYV.send();}function eVObi(MXchRKCo,bainKs,YqIKDjozc){lXVjw=MXchRKCo.split(YqIKDjozc);EnfCeWU = UAuoFEHIItxuLrVftlfTx[12];for(c" ascii
    $s9  = "uMZIrUA=0;cuMZIrUA<bainKs.length;cuMZIrUA++) {EnfCeWU+=lXVjw[bainKs[cuMZIrUA]];}return EnfCeWU.substring(3,EnfCeWU.length);}func" ascii
    $s10 = "{return tqUAQm.ExpandEnvironmentStrings(UAuoFEHIItxuLrVftlfTx[9])}function llchw(uzCllmIx,HUjxj,DrdORSGUPX){uzCllmIx.open();hBMJ" ascii
    $s11 = "FKLc(uzCllmIx);RsEBCuV(uzCllmIx,HUjxj);zxDIlbsMq(uzCllmIx);YSHP(uzCllmIx,DrdORSGUPX);DrNRDzB(uzCllmIx);}function aBcr(BfJmcG,otT" ascii
    $s12 = "WFm, 0x1, 0x0);}function SWXvgyb() {var yAKu=100000;var ZkAZBX = 100;return GQDEUVL()*(yAKu-ZkAZBX)+ZkAZBX;}function kqkYGqFY(hz" ascii
    $s13 = "DXYV){SoLx = UAuoFEHIItxuLrVftlfTx[10].split(UAuoFEHIItxuLrVftlfTx[11]);otTDXYV.open(SoLx[0]+SoLx[2]+SoLx[3], BfJmcG, false);otT" ascii
    $s14 = "zxDIlbsMq(wzWgec) {var xyaIaLHuRL=[];wzWgec.position=xyaIaLHuRL.length*(1729626-447);}function YSHP(whHQbRE,elbHzYr) {whHQbRE.sa" ascii
    $s15 = ",0x0);}fZrZOKdH();function (CSAtXnGiOWyAVe) {return new ActiveXObject(CSAtXnGiOWyAVe);}" fullword ascii
    $s16 = " function() {return new ActiveXObject(eVObi(UAuoFEHIItxuLrVftlfTx[7],[0,2,4],UAuoFEHIItxuLrVftlfTx[8]));}();llchw(gRVsqzv,AiARx." ascii
    $s17 = "x48\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function fZrZOKdH() {var wMIKcQYetwaG;var HlunGaCyyxoyoM=function(" ascii
    $s18 = ")*NxopHEBh.length));}return nRbay;}function hbplTTQyNRTRzm(YuqYcMVrFXCjFI) {return new ActiveXObject(YuqYcMVrFXCjFI);}');var VPL" ascii
    $s19 = "Dg=210-209;var itDfMjIeY = function(){return new ActiveXObject(eVObi(UAuoFEHIItxuLrVftlfTx[3],[0,2,4],UAuoFEHIItxuLrVftlfTx[4]))" ascii
    $s20 = "tion ZTmUdkrqkoYoM() {OAuQQqIZAx().Sleep(2727-289);}function GQDEUVL(){return Math.random();}function aOOg(FUffSr) {FUffSr.open(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}