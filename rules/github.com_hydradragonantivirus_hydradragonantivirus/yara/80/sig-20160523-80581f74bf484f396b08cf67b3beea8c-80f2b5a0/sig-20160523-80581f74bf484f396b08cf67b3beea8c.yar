rule sig_20160523_80581f74bf484f396b08cf67b3beea8c {
  meta:
    description = "datamaliciousorder - file 20160523_80581f74bf484f396b08cf67b3beea8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a7cff050464f145f0bc4fcb25268ff0ed76f984891ebcdbb42e8c1887fca21b"

  strings:
    $s1  = "function LIAJIRcg(fiJgI) {var rPhvEkjW=EUBFeDFCUKOqlJBkvUEC[2];for(var GmIsK=0;GmIsK<fiJgI;GmIsK++){PFmzi+=rPhvEkjW.charAt(Math." ascii
    $s2  = "function LIAJIRcg(fiJgI) {var rPhvEkjW=EUBFeDFCUKOqlJBkvUEC[2];for(var GmIsK=0;GmIsK<fiJgI;GmIsK++){PFmzi+=rPhvEkjW.charAt(Math." ascii
    $s3  = "function VjwEnfCeWU(oPuGQDEU,VLaOOgFUffSr) {oPuGQDEU.Run(VLaOOgFUffSr, 0x1, 0x0);}" fullword ascii
    $s4  = "function VVPCKx(DIBEVr){return DIBEVr.ExpandEnvironmentStrings(EUBFeDFCUKOqlJBkvUEC[10])}" fullword ascii
    $s5  = "floor(Math.random()*rPhvEkjW.length));}return PFmzi;}" fullword ascii
    $s6  = "function IxHU(jxjDrd) {jxjDrd.open();}" fullword ascii
    $s7  = "mgJh<baolQW.length;qUAQmgJh++) {oemnRml+=ylyIz[baolQW[qUAQmgJh]];}return oemnRml.substring(3,oemnRml.length);}" fullword ascii
    $s8  = "function ORSGUPXa(BcrBfJmcG) {BcrBfJmcG.type=1;}" fullword ascii
    $s9  = "if (USuJDEE==0) break;" fullword ascii
    $s10 = "function sqzv(rYroZP,JYuZvzh){qRor = EUBFeDFCUKOqlJBkvUEC[11].split(EUBFeDFCUKOqlJBkvUEC[12]);JYuZvzh.open(qRor[0]+qRor[2]+qRor[" ascii
    $s11 = "function otTDXYV(SoLx,atTsX) {SoLx.write(atTsX);}" fullword ascii
    $s12 = "function wuzCllm(){return Math.random();}" fullword ascii
    $s13 = "function idVEc(aXdXgeRS,baolQW,jbdFWMUlt){ylyIz=aXdXgeRS.split(jbdFWMUlt);oemnRml = EUBFeDFCUKOqlJBkvUEC[13];for(qUAQmgJh=0;qUAQ" ascii
    $s14 = "function hpHpjiXmC(DNTjJEVbY,HwxVbIp,yqqWgFFi){" fullword ascii
    $s15 = "function QgYjKKhIG(qlTIlb) {var NxeVObiMXc=[];qlTIlb.position=NxeVObiMXc.length*(6312505-196);}" fullword ascii
    $s16 = "function lhQja(DIBEVr){return new ActiveXObject(DIBEVr);}" fullword ascii
    $s17 = "3], rYroZP, false);JYuZvzh.send();}" fullword ascii
    $s18 = "function gitDf(MjIeYFQI,CZAWK,jJAiARxgRV){IxHU(MjIeYFQI);ORSGUPXa(MjIeYFQI);otTDXYV(MjIeYFQI,CZAWK);QgYjKKhIG(MjIeYFQI);hRKC(MjI" ascii
    $s19 = "function sqzv(rYroZP,JYuZvzh){qRor = EUBFeDFCUKOqlJBkvUEC[11].split(EUBFeDFCUKOqlJBkvUEC[12]);JYuZvzh.open(qRor[0]+qRor[2]+qRor[" ascii
    $s20 = "try{USuJDEE=hpHpjiXmC(ADQKD[LEDd], zGyjHzo() + EUBFeDFCUKOqlJBkvUEC[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}