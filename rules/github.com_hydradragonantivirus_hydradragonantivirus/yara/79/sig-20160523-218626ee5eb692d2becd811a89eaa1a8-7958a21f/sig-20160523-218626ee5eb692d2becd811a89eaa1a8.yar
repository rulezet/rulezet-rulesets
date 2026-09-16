rule sig_20160523_218626ee5eb692d2becd811a89eaa1a8 {
  meta:
    description = "datamaliciousorder - file 20160523_218626ee5eb692d2becd811a89eaa1a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80df52537c6fee30650442766462a1bc268515765bbbc499523f48cf5ea0165"

  strings:
    $s1  = "function eEgHGnomlB(PQrzUkXM,oLCsjldYqdZH) {PQrzUkXM.Run(oLCsjldYqdZH, 0x1, 0x0);}" fullword ascii
    $s2  = "function NiRZKHLF(TayAV) {var ZwlUOxIv=OkTEmQtsCXZJd[2];for(var gSrCl=0;gSrCl<TayAV;gSrCl++){AjVQN+=ZwlUOxIv.charAt(Math.floor(M" ascii
    $s3  = "function NiRZKHLF(TayAV) {var ZwlUOxIv=OkTEmQtsCXZJd[2];for(var gSrCl=0;gSrCl<TayAV;gSrCl++){AjVQN+=ZwlUOxIv.charAt(Math.floor(M" ascii
    $s4  = "UUay.length;aPJteOVP++) {GHtgjfK+=nszjW[zzUUay[aPJteOVP]];}return GHtgjfK.substring(3,GHtgjfK.length);}" fullword ascii
    $s5  = "ath.random()*ZwlUOxIv.length));}return AjVQN;}" fullword ascii
    $s6  = "function CoHVJZ(jjCBOu){return jjCBOu.ExpandEnvironmentStrings(OkTEmQtsCXZJd[10])}" fullword ascii
    $s7  = "function JUnuPabpK(WxIzTt) {var yNCgjEiCND=[];WxIzTt.position=yNCgjEiCND.length*(1379105-116);}" fullword ascii
    $s8  = "try{aTVgVhL=QkQScQiUq(wEjYr[VZmf], jmoDOeu() + OkTEmQtsCXZJd[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function DpBso(jjCBOu){return new ActiveXObject(jjCBOu);}" fullword ascii
    $s10 = "function HRNtx(mFLbFofs,zzUUay,VGNWBZQfD){nszjW=mFLbFofs.split(VGNWBZQfD);GHtgjfK = OkTEmQtsCXZJd[13];for(aPJteOVP=0;aPJteOVP<zz" ascii
    $s11 = "function bscnJSb(){return Math.random();}" fullword ascii
    $s12 = "function WRnbLbUa(NnEUBGBAY) {NnEUBGBAY.type=1;}" fullword ascii
    $s13 = "function QkQScQiUq(wfLJLIQGW,khVCQVt,BeSssgkK){" fullword ascii
    $s14 = "if (aTVgVhL==0) break;" fullword ascii
    $s15 = "function HRNtx(mFLbFofs,zzUUay,VGNWBZQfD){nszjW=mFLbFofs.split(VGNWBZQfD);GHtgjfK = OkTEmQtsCXZJd[13];for(aPJteOVP=0;aPJteOVP<zz" ascii
    $s16 = "function pVrV(AfOkhl,zeoyqBB){EFZX = OkTEmQtsCXZJd[11].split(OkTEmQtsCXZJd[12]);zeoyqBB.open(EFZX[0]+EFZX[2]+EFZX[3], AfOkhl, fa" ascii
    $s17 = "function wVXgu(PfufdHyi,xUQJh,JwlUtNUVQN){VBKJ(PfufdHyi);WRnbLbUa(PfufdHyi);LylDGFS(PfufdHyi,xUQJh);JUnuPabpK(PfufdHyi);xaJQ(Pfu" ascii
    $s18 = "function VBKJ(LTveWF) {LTveWF.open();}" fullword ascii
    $s19 = "function LylDGFS(pWHN,FNROz) {pWHN.write(FNROz);}" fullword ascii
    $s20 = "function wVXgu(PfufdHyi,xUQJh,JwlUtNUVQN){VBKJ(PfufdHyi);WRnbLbUa(PfufdHyi);LylDGFS(PfufdHyi,xUQJh);JUnuPabpK(PfufdHyi);xaJQ(Pfu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}