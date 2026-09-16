rule sig_20160520_b1b220d76e0851f2c19dfb617c4f46cf {
  meta:
    description = "datamaliciousorder - file 20160520_b1b220d76e0851f2c19dfb617c4f46cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9e79a4253b494966f0f2c0e24774acb8820dd038f7389f6fc7012d54f4f2630"

  strings:
    $s1  = "function kiGJZpmU(sWamp) {var JFbnFpfm=RGoGZwZAoMvEd[2];for(var qOSIV=0;qOSIV<sWamp;qOSIV++){oeBZA+=JFbnFpfm.charAt(Math.floor(M" ascii
    $s2  = "function kiGJZpmU(sWamp) {var JFbnFpfm=RGoGZwZAoMvEd[2];for(var qOSIV=0;qOSIV<sWamp;qOSIV++){oeBZA+=JFbnFpfm.charAt(Math.floor(M" ascii
    $s3  = "pdqP.length;XRGVFRJb++) {xbjiMmu+=gbvjZ[ampdqP[XRGVFRJb]];}return xbjiMmu.substring(3,xbjiMmu.length);}" fullword ascii
    $s4  = "ath.random()*JFbnFpfm.length));}return oeBZA;}" fullword ascii
    $s5  = "function lKdwnk(MyvXyi){return MyvXyi.ExpandEnvironmentStrings(RGoGZwZAoMvEd[10])}" fullword ascii
    $s6  = "function AtGRi(UfvvUMgl,ampdqP,NVvhTltBz){gbvjZ=UfvvUMgl.split(NVvhTltBz);xbjiMmu = RGoGZwZAoMvEd[13];for(XRGVFRJb=0;XRGVFRJb<am" ascii
    $s7  = "function pfrJEkt() {var WPbC=100000;var wLCxWM = 100;return Math.random()*(WPbC-wLCxWM)+wLCxWM;}" fullword ascii
    $s8  = "function uGBFr(BQWEgCTM,hcVVQ,iZJRlGhvfM){BQWEgCTM.open();BQWEgCTM.type = 1;BQWEgCTM.write(hcVVQ);BQWEgCTM.position = 0;BQWEgCTM" ascii
    $s9  = "function UXwCHWzoo(lvGgpnPag,HBpiIaQ,uVYWoyGy){" fullword ascii
    $s10 = "function AtGRi(UfvvUMgl,ampdqP,NVvhTltBz){gbvjZ=UfvvUMgl.split(NVvhTltBz);xbjiMmu = RGoGZwZAoMvEd[13];for(XRGVFRJb=0;XRGVFRJb<am" ascii
    $s11 = "function UqgR(aLgSgs,yopwaeg){KcLL = RGoGZwZAoMvEd[11].split(RGoGZwZAoMvEd[12]);yopwaeg.open(KcLL[0]+KcLL[2]+KcLL[3], aLgSgs, fa" ascii
    $s12 = "function xmJyB(MyvXyi){return new ActiveXObject(MyvXyi);}" fullword ascii
    $s13 = "function UqgR(aLgSgs,yopwaeg){KcLL = RGoGZwZAoMvEd[11].split(RGoGZwZAoMvEd[12]);yopwaeg.open(KcLL[0]+KcLL[2]+KcLL[3], aLgSgs, fa" ascii
    $s14 = "try{UXwCHWzoo(FCmqy[mVDB], pfrJEkt() + RGoGZwZAoMvEd[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function uGBFr(BQWEgCTM,hcVVQ,iZJRlGhvfM){BQWEgCTM.open();BQWEgCTM.type = 1;BQWEgCTM.write(hcVVQ);BQWEgCTM.position = 0;BQWEgCTM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}