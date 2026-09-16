rule sig_20160523_064885a337bec38f15604c345d001098 {
  meta:
    description = "datamaliciousorder - file 20160523_064885a337bec38f15604c345d001098.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "623ef63177b2489f8370761af5b630432fe70a573e3b99b495cce4610b1f6450"

  strings:
    $s1  = "function yNwidaWSsI(dxdfpdvh,DngitiuYJsYW) {dxdfpdvh.Run(DngitiuYJsYW, 0x1, 0x0);}" fullword ascii
    $s2  = "function Hmsuwwzw(dAkws) {var ydeJNjHT=qgloVgMdqMYrnsz[2];for(var tiPoN=0;tiPoN<dAkws;tiPoN++){dPLUB+=ydeJNjHT.charAt(Math.floor" ascii
    $s3  = "function Hmsuwwzw(dAkws) {var ydeJNjHT=qgloVgMdqMYrnsz[2];for(var tiPoN=0;tiPoN<dAkws;tiPoN++){dPLUB+=ydeJNjHT.charAt(Math.floor" ascii
    $s4  = "OpzvCD.length;SdlNAgpN++) {RNEcKFf+=SEZIG[OpzvCD[SdlNAgpN]];}return RNEcKFf.substring(3,RNEcKFf.length);}" fullword ascii
    $s5  = "function CRQvw(AHHYkQhu,OpzvCD,OotEFJFPd){SEZIG=AHHYkQhu.split(OotEFJFPd);RNEcKFf = qgloVgMdqMYrnsz[13];for(SdlNAgpN=0;SdlNAgpN<" ascii
    $s6  = "function CRQvw(AHHYkQhu,OpzvCD,OotEFJFPd){SEZIG=AHHYkQhu.split(OotEFJFPd);RNEcKFf = qgloVgMdqMYrnsz[13];for(SdlNAgpN=0;SdlNAgpN<" ascii
    $s7  = "function pZtOFxJ(VIEK,bQTCs) {VIEK.write(bQTCs);}" fullword ascii
    $s8  = ", false);pyVlxSP.send();}" fullword ascii
    $s9  = "function fInHWA(AUTkEm){return AUTkEm.ExpandEnvironmentStrings(qgloVgMdqMYrnsz[10])}" fullword ascii
    $s10 = "try{xPeNqKG=FIPVurZCT(mTIaw[mtar], pwKgTrX() + qgloVgMdqMYrnsz[9], 1)}catch(e){}; " fullword ascii
    $s11 = "if (xPeNqKG==0) break;" fullword ascii
    $s12 = "function YIre(fIXpYs,pyVlxSP){jaiX = qgloVgMdqMYrnsz[11].split(qgloVgMdqMYrnsz[12]);pyVlxSP.open(jaiX[0]+jaiX[2]+jaiX[3], fIXpYs" ascii
    $s13 = "function pwKgTrX() {var WpJl=100000;var VPrAKe = 100;return qihSQPV()*(WpJl-VPrAKe)+VPrAKe;}" fullword ascii
    $s14 = "function YIre(fIXpYs,pyVlxSP){jaiX = qgloVgMdqMYrnsz[11].split(qgloVgMdqMYrnsz[12]);pyVlxSP.open(jaiX[0]+jaiX[2]+jaiX[3], fIXpYs" ascii
    $s15 = "function XlHHs(AUTkEm){return new ActiveXObject(AUTkEm);}" fullword ascii
    $s16 = "function ToQFloDYJ(RwlEwz) {var BQbrHJecNb=[];RwlEwz.position=BQbrHJecNb.length*(1861388-640);}" fullword ascii
    $s17 = "function JJXJ(yCrOHy) {yCrOHy.open();}" fullword ascii
    $s18 = "function VvxRy(MGouzSjy,FNmeC,vKcqvnMtSi){JJXJ(MGouzSjy);icjcjREu(MGouzSjy);pZtOFxJ(MGouzSjy,FNmeC);ToQFloDYJ(MGouzSjy);DnFl(MGo" ascii
    $s19 = "function FIPVurZCT(pPJNkmjFI,ziLwUhl,KobKlarn){" fullword ascii
    $s20 = "function icjcjREu(DaOedTnlV) {DaOedTnlV.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}