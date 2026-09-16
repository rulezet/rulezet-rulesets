rule sig_20160523_f197c08430d1f4f7f60d112eceb8d69b {
  meta:
    description = "datamaliciousorder - file 20160523_f197c08430d1f4f7f60d112eceb8d69b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3edae2699069ffddb7598eaa72fdd2293f43d291c7aa7a8dc18a08850a9dc897"

  strings:
    $s1  = "function LBSHAKyMLG(kRDjYCOJ,pXDafGHyTKlV) {kRDjYCOJ.Run(pXDafGHyTKlV, 0x1, 0x0);}" fullword ascii
    $s2  = "function yROeEvZE(uTsNl) {var IYPVOwxQ=dxCsWNiMxaTWcziNfxBfh[13];for(var ISXNp=0;ISXNp<uTsNl;ISXNp++){PYfiu+=IYPVOwxQ.charAt(Mat" ascii
    $s3  = "function yROeEvZE(uTsNl) {var IYPVOwxQ=dxCsWNiMxaTWcziNfxBfh[13];for(var ISXNp=0;ISXNp<uTsNl;ISXNp++){PYfiu+=IYPVOwxQ.charAt(Mat" ascii
    $s4  = "function AiVWV(uHrAabUF,yjSeL,KWnoHqZdGN){TQZp(uHrAabUF);RtziLbks(uHrAabUF);hsydKZZ(uHrAabUF,yjSeL);NjshKmLTg(uHrAabUF);TPDg(uHr" ascii
    $s5  = "function ECcWG(MLWCQKOe,eyDwvZ,UrgLSafGb){ptIsk=MLWCQKOe.split(UrgLSafGb);MatycUe = dxCsWNiMxaTWcziNfxBfh[12];for(iHkBaGuX=0;iHk" ascii
    $s6  = "function hsydKZZ(KrOr,AVJen) {KrOr.write(AVJen);}" fullword ascii
    $s7  = "function ECcWG(MLWCQKOe,eyDwvZ,UrgLSafGb){ptIsk=MLWCQKOe.split(UrgLSafGb);MatycUe = dxCsWNiMxaTWcziNfxBfh[12];for(iHkBaGuX=0;iHk" ascii
    $s8  = "if(FNCw>LXYFV.length) break;" fullword ascii
    $s9  = "function AiVWV(uHrAabUF,yjSeL,KWnoHqZdGN){TQZp(uHrAabUF);RtziLbks(uHrAabUF);hsydKZZ(uHrAabUF,yjSeL);NjshKmLTg(uHrAabUF);TPDg(uHr" ascii
    $s10 = "function GDMx(ZODhxg,laREpQz){ITNn = dxCsWNiMxaTWcziNfxBfh[10].split(dxCsWNiMxaTWcziNfxBfh[11]);laREpQz.open(ITNn[0]+ITNn[2]+ITN" ascii
    $s11 = "function livzmd(fhTRoc){return fhTRoc.ExpandEnvironmentStrings(dxCsWNiMxaTWcziNfxBfh[9])}" fullword ascii
    $s12 = "function exxEyfK(){return Math.random();}" fullword ascii
    $s13 = "function jMqWbHz(EGPRx) {EGPRx.close();}" fullword ascii
    $s14 = "function RtziLbks(MujZdqvIw) {MujZdqvIw.type=1;}" fullword ascii
    $s15 = "function NjshKmLTg(roJRwF) {var pkZRVdYBoM=[];roJRwF.position=pkZRVdYBoM.length*(3722706-527);}" fullword ascii
    $s16 = "function TQZp(CmreFr) {CmreFr.open();}" fullword ascii
    $s17 = "function bsskXlg() {var KXtV=100000;var ZMihhC = 100;return exxEyfK()*(KXtV-ZMihhC)+ZMihhC;}" fullword ascii
    $s18 = "function GDMx(ZODhxg,laREpQz){ITNn = dxCsWNiMxaTWcziNfxBfh[10].split(dxCsWNiMxaTWcziNfxBfh[11]);laREpQz.open(ITNn[0]+ITNn[2]+ITN" ascii
    $s19 = "BaGuX<eyDwvZ.length;iHkBaGuX++) {MatycUe+=ptIsk[eyDwvZ[iHkBaGuX]];}return MatycUe.substring(3,MatycUe.length);}" fullword ascii
    $s20 = "n[3], ZODhxg, false);laREpQz.send();}" fullword ascii

  condition:
    uint16(0) == 0x0b27 and
    8 of them
}