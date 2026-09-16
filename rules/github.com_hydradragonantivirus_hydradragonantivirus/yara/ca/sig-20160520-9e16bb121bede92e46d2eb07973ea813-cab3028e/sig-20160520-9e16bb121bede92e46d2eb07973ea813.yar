rule sig_20160520_9e16bb121bede92e46d2eb07973ea813 {
  meta:
    description = "datamaliciousorder - file 20160520_9e16bb121bede92e46d2eb07973ea813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cfda3a05f2c72776f098f5cf053645bd223bd153c313667ea746aa2ca72ee9e"

  strings:
    $s1  = "function JqsMVgvk(ppgRl) {var qESAhuZA=hzAPIhAsWHTqlLwh[2];for(var mIxcF=0;mIxcF<ppgRl;mIxcF++){XXzIt+=qESAhuZA.charAt(Math.floo" ascii
    $s2  = "function JqsMVgvk(ppgRl) {var qESAhuZA=hzAPIhAsWHTqlLwh[2];for(var mIxcF=0;mIxcF<ppgRl;mIxcF++){XXzIt+=qESAhuZA.charAt(Math.floo" ascii
    $s3  = "function sWqO(SnlAEl,UyAvcbd){VUZn = hzAPIhAsWHTqlLwh[11].split(hzAPIhAsWHTqlLwh[12]);UyAvcbd.open(VUZn[0]+VUZn[2]+VUZn[3], SnlA" ascii
    $s4  = "try{xWrzuhtTn(MplzO[axfr], rkXvLiX() + hzAPIhAsWHTqlLwh[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function eMkTJ(vGkxyKKM,sCFvdM,FOctWKocq){LHKuo=vGkxyKKM.split(FOctWKocq);CyggdLa = hzAPIhAsWHTqlLwh[13];for(AlRXdStD=0;AlRXdStD" ascii
    $s6  = "function sWqO(SnlAEl,UyAvcbd){VUZn = hzAPIhAsWHTqlLwh[11].split(hzAPIhAsWHTqlLwh[12]);UyAvcbd.open(VUZn[0]+VUZn[2]+VUZn[3], SnlA" ascii
    $s7  = "El, false);UyAvcbd.send();}" fullword ascii
    $s8  = "function rkXvLiX() {var NKVx=100000;var tXPVtM = 100;return Math.random()*(NKVx-tXPVtM)+tXPVtM;}" fullword ascii
    $s9  = "r(Math.random()*qESAhuZA.length));}return XXzIt;}" fullword ascii
    $s10 = "<sCFvdM.length;AlRXdStD++) {CyggdLa+=LHKuo[sCFvdM[AlRXdStD]];}return CyggdLa.substring(3,CyggdLa.length);}" fullword ascii
    $s11 = "function KSBmHG(ZFUkyJ){return ZFUkyJ.ExpandEnvironmentStrings(hzAPIhAsWHTqlLwh[10])}" fullword ascii
    $s12 = "function yxZDE(YImhZeME,DxVWq,zgFpvjEhXx){YImhZeME.open();YImhZeME.type = 1;YImhZeME.write(DxVWq);YImhZeME.position = 0;YImhZeME" ascii
    $s13 = "function tHXaR(ZFUkyJ){return new ActiveXObject(ZFUkyJ);}" fullword ascii
    $s14 = "function yxZDE(YImhZeME,DxVWq,zgFpvjEhXx){YImhZeME.open();YImhZeME.type = 1;YImhZeME.write(DxVWq);YImhZeME.position = 0;YImhZeME" ascii
    $s15 = "function eMkTJ(vGkxyKKM,sCFvdM,FOctWKocq){LHKuo=vGkxyKKM.split(FOctWKocq);CyggdLa = hzAPIhAsWHTqlLwh[13];for(AlRXdStD=0;AlRXdStD" ascii
    $s16 = "function xWrzuhtTn(FaNnjjNgl,vWdDGUP,CpMCbvdb){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}