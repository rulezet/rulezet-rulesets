rule sig_20160523_0a61e986acf31cef3d9fe94398728121 {
  meta:
    description = "datamaliciousorder - file 20160523_0a61e986acf31cef3d9fe94398728121.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "025b58117f348666283b6b2dabba8b98a0c1fcbcd3e8c030c69ef92e19b557b9"

  strings:
    $s1  = "function TFOsLURThR(lfZvzMFd,PbSOJJcboUcO) {lfZvzMFd.Run(PbSOJJcboUcO, 0x1, 0x0);}" fullword ascii
    $s2  = "function EzBUORNT(uIMKV) {var cJjpFoKc=eCUlAcQtAzJMEAueWxdczkYY[2];for(var vNeee=0;vNeee<uIMKV;vNeee++){SIVJO+=cJjpFoKc.charAt(M" ascii
    $s3  = "function EzBUORNT(uIMKV) {var cJjpFoKc=eCUlAcQtAzJMEAueWxdczkYY[2];for(var vNeee=0;vNeee<uIMKV;vNeee++){SIVJO+=cJjpFoKc.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*cJjpFoKc.length));}return SIVJO;}" fullword ascii
    $s5  = "function oQASy(lnIrzkhl,ftAYav,zWLuoXiVG){njfFV=lnIrzkhl.split(zWLuoXiVG);qKqsCqI = eCUlAcQtAzJMEAueWxdczkYY[13];for(sRcLaJvq=0;" ascii
    $s6  = "function AyiC(mGbSKW,iVRXodg){PFgB = eCUlAcQtAzJMEAueWxdczkYY[11].split(eCUlAcQtAzJMEAueWxdczkYY[12]);iVRXodg.open(PFgB[0]+PFgB[" ascii
    $s7  = "function vcqvTbEs(SSGKkAZhn) {SSGKkAZhn.type=1;}" fullword ascii
    $s8  = "function NVfkGSoMc(pFtcSO) {var yeEbTfgdWF=[];pFtcSO.position=yeEbTfgdWF.length*(7050010-341);}" fullword ascii
    $s9  = "function BgyB(vVStTIV,dzeZgst) {vVStTIV.saveToFile(dzeZgst, 2);}" fullword ascii
    $s10 = "function fdciW(WkWLPEbU,Lvpwp,weRHQnbrqg){Fljl(WkWLPEbU);vcqvTbEs(WkWLPEbU);vQUTEJL(WkWLPEbU,Lvpwp);NVfkGSoMc(WkWLPEbU);BgyB(WkW" ascii
    $s11 = "try{UUFNhgx=roEzGnEky(ioQEG[Scqf], YsyZXyS() + eCUlAcQtAzJMEAueWxdczkYY[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function WzepdGM(boAXp) {boAXp.close();}" fullword ascii
    $s13 = "function YsyZXyS() {var zbis=100000;var SDTbov = 100;return tvGvHlW()*(zbis-SDTbov)+SDTbov;}" fullword ascii
    $s14 = "sRcLaJvq<ftAYav.length;sRcLaJvq++) {qKqsCqI+=njfFV[ftAYav[sRcLaJvq]];}return qKqsCqI.substring(3,qKqsCqI.length);}" fullword ascii
    $s15 = "function roEzGnEky(RzsVAUjNh,RKiDnAS,iIKeLZTB){" fullword ascii
    $s16 = "function vQUTEJL(tyIO,GctRX) {tyIO.write(GctRX);}" fullword ascii
    $s17 = "function AyiC(mGbSKW,iVRXodg){PFgB = eCUlAcQtAzJMEAueWxdczkYY[11].split(eCUlAcQtAzJMEAueWxdczkYY[12]);iVRXodg.open(PFgB[0]+PFgB[" ascii
    $s18 = "function fdciW(WkWLPEbU,Lvpwp,weRHQnbrqg){Fljl(WkWLPEbU);vcqvTbEs(WkWLPEbU);vQUTEJL(WkWLPEbU,Lvpwp);NVfkGSoMc(WkWLPEbU);BgyB(WkW" ascii
    $s19 = "2]+PFgB[3], mGbSKW, false);iVRXodg.send();}" fullword ascii
    $s20 = "function oQASy(lnIrzkhl,ftAYav,zWLuoXiVG){njfFV=lnIrzkhl.split(zWLuoXiVG);qKqsCqI = eCUlAcQtAzJMEAueWxdczkYY[13];for(sRcLaJvq=0;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}