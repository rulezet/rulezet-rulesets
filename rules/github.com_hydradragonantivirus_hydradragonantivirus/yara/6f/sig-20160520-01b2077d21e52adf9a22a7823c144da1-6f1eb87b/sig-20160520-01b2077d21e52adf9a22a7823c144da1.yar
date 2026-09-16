rule sig_20160520_01b2077d21e52adf9a22a7823c144da1 {
  meta:
    description = "datamaliciousorder - file 20160520_01b2077d21e52adf9a22a7823c144da1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "182dc0a3035d7d18533bd8130c60085aef1adecbb03dbfb93e22613da08b5ee0"

  strings:
    $s1  = "function dxiduHGS(YjzKZ) {var UMmjgQAO=SyjoanlqQKfgFIkZQICAZ[2];for(var LKhyb=0;LKhyb<YjzKZ;LKhyb++){TkyTp+=UMmjgQAO.charAt(Math" ascii
    $s2  = "function dxiduHGS(YjzKZ) {var UMmjgQAO=SyjoanlqQKfgFIkZQICAZ[2];for(var LKhyb=0;LKhyb<YjzKZ;LKhyb++){TkyTp+=UMmjgQAO.charAt(Math" ascii
    $s3  = "function shGzkMV() {var bIKj=100000;var ePmmHm = 100;return Math.random()*(bIKj-ePmmHm)+ePmmHm;}" fullword ascii
    $s4  = "try{CTgmAjKlp(HzjWb[lkGs], shGzkMV() + SyjoanlqQKfgFIkZQICAZ[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function lhkoz(RyWMFT){return new ActiveXObject(RyWMFT);}" fullword ascii
    $s6  = ".floor(Math.random()*UMmjgQAO.length));}return TkyTp;}" fullword ascii
    $s7  = "P[3], YYzsGC, false);GQIrucW.send();}" fullword ascii
    $s8  = "function CTgmAjKlp(JlqzfZakJ,UnZfmBZ,FUQNUkDw){" fullword ascii
    $s9  = "function TWRSL(IqelRIrk,xyqaY,TmztvRafmr){IqelRIrk.open();IqelRIrk.type = 1;IqelRIrk.write(xyqaY);IqelRIrk.position = 0;IqelRIrk" ascii
    $s10 = "uVIZa<bVQcHT.length;YBYuVIZa++) {zBAJtze+=fBJsp[bVQcHT[YBYuVIZa]];}return zBAJtze.substring(3,zBAJtze.length);}" fullword ascii
    $s11 = "function TWRSL(IqelRIrk,xyqaY,TmztvRafmr){IqelRIrk.open();IqelRIrk.type = 1;IqelRIrk.write(xyqaY);IqelRIrk.position = 0;IqelRIrk" ascii
    $s12 = "function uhUw(YYzsGC,GQIrucW){quNP = SyjoanlqQKfgFIkZQICAZ[11].split(SyjoanlqQKfgFIkZQICAZ[12]);GQIrucW.open(quNP[0]+quNP[2]+quN" ascii
    $s13 = "function vjpvoC(RyWMFT){return RyWMFT.ExpandEnvironmentStrings(SyjoanlqQKfgFIkZQICAZ[10])}" fullword ascii
    $s14 = "function uhUw(YYzsGC,GQIrucW){quNP = SyjoanlqQKfgFIkZQICAZ[11].split(SyjoanlqQKfgFIkZQICAZ[12]);GQIrucW.open(quNP[0]+quNP[2]+quN" ascii
    $s15 = "function wyLBH(cdJeXPVZ,bVQcHT,yAFGyepJV){fBJsp=cdJeXPVZ.split(yAFGyepJV);zBAJtze = SyjoanlqQKfgFIkZQICAZ[13];for(YBYuVIZa=0;YBY" ascii
    $s16 = "function wyLBH(cdJeXPVZ,bVQcHT,yAFGyepJV){fBJsp=cdJeXPVZ.split(yAFGyepJV);zBAJtze = SyjoanlqQKfgFIkZQICAZ[13];for(YBYuVIZa=0;YBY" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}