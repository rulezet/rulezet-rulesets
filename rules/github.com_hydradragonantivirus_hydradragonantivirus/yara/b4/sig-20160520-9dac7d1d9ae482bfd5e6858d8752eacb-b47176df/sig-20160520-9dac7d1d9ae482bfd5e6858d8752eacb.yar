rule sig_20160520_9dac7d1d9ae482bfd5e6858d8752eacb {
  meta:
    description = "datamaliciousorder - file 20160520_9dac7d1d9ae482bfd5e6858d8752eacb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dced63cbbf58ba45ad606215cd6fb525814fed57e628168c3a67e04b1a58b88d"

  strings:
    $s1  = "function HwNSobun(MYiuy) {var smcxOsGh=aHhfQddFFDgp[2];for(var qMWBF=0;qMWBF<MYiuy;qMWBF++){fqdKJ+=smcxOsGh.charAt(Math.floor(Ma" ascii
    $s2  = "function HwNSobun(MYiuy) {var smcxOsGh=aHhfQddFFDgp[2];for(var qMWBF=0;qMWBF<MYiuy;qMWBF++){fqdKJ+=smcxOsGh.charAt(Math.floor(Ma" ascii
    $s3  = "function uNzFM(bzfuqn){return new ActiveXObject(bzfuqn);}" fullword ascii
    $s4  = "function PfjA(FHetBj,FTzqAqZ){iYDZ = aHhfQddFFDgp[11].split(aHhfQddFFDgp[12]);FTzqAqZ.open(iYDZ[0]+iYDZ[2]+iYDZ[3], FHetBj, fals" ascii
    $s5  = "if (HGSDyLl==0) break;" fullword ascii
    $s6  = "function uKdWKz(bzfuqn){return bzfuqn.ExpandEnvironmentStrings(aHhfQddFFDgp[10])}" fullword ascii
    $s7  = "function PfjA(FHetBj,FTzqAqZ){iYDZ = aHhfQddFFDgp[11].split(aHhfQddFFDgp[12]);FTzqAqZ.open(iYDZ[0]+iYDZ[2]+iYDZ[3], FHetBj, fals" ascii
    $s8  = "function oGvNE(NXWjLgrD,HfPLe,GHdiWMFyKv){NXWjLgrD.open();NXWjLgrD.type = 1;NXWjLgrD.write(HfPLe);NXWjLgrD.position = 0;NXWjLgrD" ascii
    $s9  = "th.random()*smcxOsGh.length));}return fqdKJ;}" fullword ascii
    $s10 = "function VpktWur() {var OXvw=100000;var vpRFzQ = 100;return Math.random()*(OXvw-vpRFzQ)+vpRFzQ;}" fullword ascii
    $s11 = "function mZlPWPqpf(JOKEpBhKM,iiMSJry,ZCOeZLcq){" fullword ascii
    $s12 = "try{HGSDyLl=mZlPWPqpf(Ucjxz[zAKj], VpktWur() + aHhfQddFFDgp[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function oGvNE(NXWjLgrD,HfPLe,GHdiWMFyKv){NXWjLgrD.open();NXWjLgrD.type = 1;NXWjLgrD.write(HfPLe);NXWjLgrD.position = 0;NXWjLgrD" ascii
    $s14 = "rYw.length;NbjCRLIV++) {iQELriR+=twrsl[KOZrYw[NbjCRLIV]];}return iQELriR.substring(3,iQELriR.length);}" fullword ascii
    $s15 = "function iIpOI(odLKgSLH,KOZrYw,mftVJPVOc){twrsl=odLKgSLH.split(mftVJPVOc);iQELriR = aHhfQddFFDgp[13];for(NbjCRLIV=0;NbjCRLIV<KOZ" ascii
    $s16 = "function iIpOI(odLKgSLH,KOZrYw,mftVJPVOc){twrsl=odLKgSLH.split(mftVJPVOc);iQELriR = aHhfQddFFDgp[13];for(NbjCRLIV=0;NbjCRLIV<KOZ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}