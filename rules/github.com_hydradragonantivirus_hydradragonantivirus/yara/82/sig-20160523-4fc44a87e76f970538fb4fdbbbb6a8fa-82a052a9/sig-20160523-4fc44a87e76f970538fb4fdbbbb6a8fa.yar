rule sig_20160523_4fc44a87e76f970538fb4fdbbbb6a8fa {
  meta:
    description = "datamaliciousorder - file 20160523_4fc44a87e76f970538fb4fdbbbb6a8fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08e8434d6ef15074f2edcf3a263971f8fc1ff47e93f32d388cf2a48ab91085a5"

  strings:
    $s1  = "function mcXRWyiwpB(xHZBnCos,DLSpRpXncRnB) {xHZBnCos.Run(DLSpRpXncRnB, 0x1, 0x0);}" fullword ascii
    $s2  = "function wtDpMrwY(dHDBn) {var mBJHHxIf=noMgMjDZsFqOuk[2];for(var OUkXg=0;OUkXg<dHDBn;OUkXg++){ZzcIp+=mBJHHxIf.charAt(Math.floor(" ascii
    $s3  = "function wtDpMrwY(dHDBn) {var mBJHHxIf=noMgMjDZsFqOuk[2];for(var OUkXg=0;OUkXg<dHDBn;OUkXg++){ZzcIp+=mBJHHxIf.charAt(Math.floor(" ascii
    $s4  = "Math.random()*mBJHHxIf.length));}return ZzcIp;}" fullword ascii
    $s5  = "function xtIxXmhE(OITNIZqdP) {OITNIZqdP.type=1;}" fullword ascii
    $s6  = "function dQcrVkh(){return Math.random();}" fullword ascii
    $s7  = "function rmIs(peQMjd,ucrGyzF){NHOr = noMgMjDZsFqOuk[11].split(noMgMjDZsFqOuk[12]);ucrGyzF.open(NHOr[0]+NHOr[2]+NHOr[3], peQMjd, " ascii
    $s8  = "function icfpILt() {var eYag=100000;var MoPpTq = 100;return dQcrVkh()*(eYag-MoPpTq)+MoPpTq;}" fullword ascii
    $s9  = "false);ucrGyzF.send();}" fullword ascii
    $s10 = "try{jChdGcY=MQJxHJEZj(AMKQp[mUNm], icfpILt() + noMgMjDZsFqOuk[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function ARcv(dwclxN) {dwclxN.open();}" fullword ascii
    $s12 = "function fqOs(LAgfHCf,drAUePb) {LAgfHCf.saveToFile(drAUePb, 2);}" fullword ascii
    $s13 = "function MQJxHJEZj(CTcfpoaFE,IVeetkG,coURjKuP){" fullword ascii
    $s14 = "function mzxjshq(CWtQm) {CWtQm.close();}" fullword ascii
    $s15 = "function dXfyC(GAptnx){return new ActiveXObject(GAptnx);}" fullword ascii
    $s16 = "function NsmcS(yggxwOEw,kOhfm,mbrBLYyCri){ARcv(yggxwOEw);xtIxXmhE(yggxwOEw);cxeVjMW(yggxwOEw,kOhfm);cLQeYpSvj(yggxwOEw);fqOs(ygg" ascii
    $s17 = "function rmIs(peQMjd,ucrGyzF){NHOr = noMgMjDZsFqOuk[11].split(noMgMjDZsFqOuk[12]);ucrGyzF.open(NHOr[0]+NHOr[2]+NHOr[3], peQMjd, " ascii
    $s18 = "if (jChdGcY==0) break;" fullword ascii
    $s19 = "function ROKUHz(GAptnx){return GAptnx.ExpandEnvironmentStrings(noMgMjDZsFqOuk[10])}" fullword ascii
    $s20 = "function cLQeYpSvj(UKAcXw) {var HvxGzERupx=[];UKAcXw.position=HvxGzERupx.length*(9590715-487);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}