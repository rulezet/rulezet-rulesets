rule sig_20160523_5045abcd5d1c440480b68b9964ab221d {
  meta:
    description = "datamaliciousorder - file 20160523_5045abcd5d1c440480b68b9964ab221d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af629ca9a58273fbbbb88fa6ab3b4d1c94d7d34f956f5ed3ca643e8e757fa8bd"

  strings:
    $s1  = "function MwjTUGtwsX(BtqoFpAW,foiOXWYgIrjS) {BtqoFpAW.Run(foiOXWYgIrjS, 0x1, 0x0);}" fullword ascii
    $s2  = "function OpzvCDOo(tEFJF) {var PdSdlNAg=fAUZhBfAKF[13];for(var pNSEZ=0;pNSEZ<tEFJF;pNSEZ++){IGRNE+=PdSdlNAg.charAt(Math.floor(Mat" ascii
    $s3  = "function OpzvCDOo(tEFJF) {var PdSdlNAg=fAUZhBfAKF[13];for(var pNSEZ=0;pNSEZ<tEFJF;pNSEZ++){IGRNE+=PdSdlNAg.charAt(Math.floor(Mat" ascii
    $s4  = "function zPcs(gPFBlR,rOGSTQJ){soTl = fAUZhBfAKF[10].split(fAUZhBfAKF[11]);rOGSTQJ.open(soTl[0]+soTl[2]+soTl[3], gPFBlR, false);r" ascii
    $s5  = "function hGahidaC(iEiNsbxuy) {iEiNsbxuy.type=1;}" fullword ascii
    $s6  = "function uYJsY(WYVdTj){return new ActiveXObject(WYVdTj);}" fullword ascii
    $s7  = "function zPcs(gPFBlR,rOGSTQJ){soTl = fAUZhBfAKF[10].split(fAUZhBfAKF[11]);rOGSTQJ.open(soTl[0]+soTl[2]+soTl[3], gPFBlR, false);r" ascii
    $s8  = "if(giti>OxIPQ.length) break;" fullword ascii
    $s9  = "function MrBLDOO(RSmk,bxKva) {RSmk.write(bxKva);}" fullword ascii
    $s10 = "i.length;wPObHPBU++) {eUtxCXJ+=iWmhj[UEYSMi[wPObHPBU]];}return eUtxCXJ.substring(3,eUtxCXJ.length);}" fullword ascii
    $s11 = "function ObnKc(GsBfyHEG,UEYSMi,mzsQCOFBw){iWmhj=GsBfyHEG.split(mzsQCOFBw);eUtxCXJ = fAUZhBfAKF[12];for(wPObHPBU=0;wPObHPBU<UEYSM" ascii
    $s12 = "function ObnKc(GsBfyHEG,UEYSMi,mzsQCOFBw){iWmhj=GsBfyHEG.split(mzsQCOFBw);eUtxCXJ = fAUZhBfAKF[12];for(wPObHPBU=0;wPObHPBU<UEYSM" ascii
    $s13 = "function xuiPdi(WYVdTj){return WYVdTj.ExpandEnvironmentStrings(fAUZhBfAKF[9])}" fullword ascii
    $s14 = "function KGAawZeMZ(olvmvB) {var NzUeaGKzSY=[];olvmvB.position=NzUeaGKzSY.length*(8477757-451);}" fullword ascii
    $s15 = "function XnMUa(iDHGrwyg,lvBtP,gEKAISXtFb){LvKh(iDHGrwyg);hGahidaC(iDHGrwyg);MrBLDOO(iDHGrwyg,lvBtP);KGAawZeMZ(iDHGrwyg);oSBs(iDH" ascii
    $s16 = "function XnMUa(iDHGrwyg,lvBtP,gEKAISXtFb){LvKh(iDHGrwyg);hGahidaC(iDHGrwyg);MrBLDOO(iDHGrwyg,lvBtP);KGAawZeMZ(iDHGrwyg);oSBs(iDH" ascii
    $s17 = "function HcsHsqU(){return Math.random();}" fullword ascii
    $s18 = "function oSBs(FMMhhnL,iTajOmd) {FMMhhnL.saveToFile(iTajOmd, 2);}" fullword ascii
    $s19 = "function LvKh(dWuWJy) {dWuWJy.open();}" fullword ascii
    $s20 = "function HRSrCRQ() {var vwAH=100000;var HYkQhu = 100;return HcsHsqU()*(vwAH-HYkQhu)+HYkQhu;}" fullword ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}