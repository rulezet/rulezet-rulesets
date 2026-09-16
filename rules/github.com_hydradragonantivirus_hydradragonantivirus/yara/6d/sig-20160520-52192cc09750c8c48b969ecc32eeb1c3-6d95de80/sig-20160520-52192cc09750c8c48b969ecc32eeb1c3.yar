rule sig_20160520_52192cc09750c8c48b969ecc32eeb1c3 {
  meta:
    description = "datamaliciousorder - file 20160520_52192cc09750c8c48b969ecc32eeb1c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a35e30eab29784cfac872c01a395e21e384674912dd051840998569c88d36d8"

  strings:
    $s1  = "function RTMhwFJp(xfLyg) {var lQmhpwKM=oXyQggeNfNcpTwQlptiqeJd[2];for(var iCxGj=0;iCxGj<xfLyg;iCxGj++){HEbkI+=lQmhpwKM.charAt(Ma" ascii
    $s2  = "function RTMhwFJp(xfLyg) {var lQmhpwKM=oXyQggeNfNcpTwQlptiqeJd[2];for(var iCxGj=0;iCxGj<xfLyg;iCxGj++){HEbkI+=lQmhpwKM.charAt(Ma" ascii
    $s3  = "EeBOqud<gMDNDm.length;oEeBOqud++) {GEmuvVC+=MldoT[gMDNDm[oEeBOqud]];}return GEmuvVC.substring(3,GEmuvVC.length);}" fullword ascii
    $s4  = "function XIcsw(NSUrGOwS,gMDNDm,vlQmBZkkc){MldoT=NSUrGOwS.split(vlQmBZkkc);GEmuvVC = oXyQggeNfNcpTwQlptiqeJd[13];for(oEeBOqud=0;o" ascii
    $s5  = "function nByxUl(HzZWTD){return HzZWTD.ExpandEnvironmentStrings(oXyQggeNfNcpTwQlptiqeJd[10])}" fullword ascii
    $s6  = "function LWmxM(HzZWTD){return new ActiveXObject(HzZWTD);}" fullword ascii
    $s7  = "function ujpGT(ZnWxYcwY,dmSMN,XwHaMSZoMs){ZnWxYcwY.open();ZnWxYcwY.type = 1;ZnWxYcwY.write(dmSMN);ZnWxYcwY.position = 0;ZnWxYcwY" ascii
    $s8  = "th.floor(Math.random()*lQmhpwKM.length));}return HEbkI;}" fullword ascii
    $s9  = "try{SMdUJafBo(OcypA[hutF], HNqbjSu() + oXyQggeNfNcpTwQlptiqeJd[9], 1)}catch(e){}; " fullword ascii
    $s10 = "+BTIa[3], XqjXMz, false);qatDaZJ.send();}" fullword ascii
    $s11 = "function HNqbjSu() {var onAT=100000;var NXWEwU = 100;return Math.random()*(onAT-NXWEwU)+NXWEwU;}" fullword ascii
    $s12 = "function SMdUJafBo(HAZlvHLFz,pKbFTuD,ZjOSsDqX){" fullword ascii
    $s13 = "function HDAH(XqjXMz,qatDaZJ){BTIa = oXyQggeNfNcpTwQlptiqeJd[11].split(oXyQggeNfNcpTwQlptiqeJd[12]);qatDaZJ.open(BTIa[0]+BTIa[2]" ascii
    $s14 = "function XIcsw(NSUrGOwS,gMDNDm,vlQmBZkkc){MldoT=NSUrGOwS.split(vlQmBZkkc);GEmuvVC = oXyQggeNfNcpTwQlptiqeJd[13];for(oEeBOqud=0;o" ascii
    $s15 = "function HDAH(XqjXMz,qatDaZJ){BTIa = oXyQggeNfNcpTwQlptiqeJd[11].split(oXyQggeNfNcpTwQlptiqeJd[12]);qatDaZJ.open(BTIa[0]+BTIa[2]" ascii
    $s16 = "function ujpGT(ZnWxYcwY,dmSMN,XwHaMSZoMs){ZnWxYcwY.open();ZnWxYcwY.type = 1;ZnWxYcwY.write(dmSMN);ZnWxYcwY.position = 0;ZnWxYcwY" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}