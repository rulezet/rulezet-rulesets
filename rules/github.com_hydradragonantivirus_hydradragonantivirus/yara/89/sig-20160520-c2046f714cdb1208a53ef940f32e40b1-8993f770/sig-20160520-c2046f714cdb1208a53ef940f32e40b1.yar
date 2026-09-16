rule sig_20160520_c2046f714cdb1208a53ef940f32e40b1 {
  meta:
    description = "datamaliciousorder - file 20160520_c2046f714cdb1208a53ef940f32e40b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "293a43af3ae9ae515f63c5bb38868896461ff7d2e8f38cc29a2d99d02a458312"

  strings:
    $s1  = "function McpZeRse(EgmVy) {var OXfzhWMQ=tCsCYLYWEBjDIOtcVhyBf[2];for(var divjU=0;divjU<EgmVy;divjU++){flQxM+=OXfzhWMQ.charAt(Math" ascii
    $s2  = "function McpZeRse(EgmVy) {var OXfzhWMQ=tCsCYLYWEBjDIOtcVhyBf[2];for(var divjU=0;divjU<EgmVy;divjU++){flQxM+=OXfzhWMQ.charAt(Math" ascii
    $s3  = "function QvLx(VadamP,GbinzNB){qoVH = tCsCYLYWEBjDIOtcVhyBf[11].split(tCsCYLYWEBjDIOtcVhyBf[12]);GbinzNB.open(qoVH[0]+qoVH[2]+qoV" ascii
    $s4  = "function QvLx(VadamP,GbinzNB){qoVH = tCsCYLYWEBjDIOtcVhyBf[11].split(tCsCYLYWEBjDIOtcVhyBf[12]);GbinzNB.open(qoVH[0]+qoVH[2]+qoV" ascii
    $s5  = "H[3], VadamP, false);GbinzNB.send();}" fullword ascii
    $s6  = "EDSQp<JTxfwL.length;dSiEDSQp++) {bZdGsWP+=nQFwT[JTxfwL[dSiEDSQp]];}return bZdGsWP.substring(3,bZdGsWP.length);}" fullword ascii
    $s7  = "try{enIwRaAWf(vfXzN[xhXi], glPHRdW() + tCsCYLYWEBjDIOtcVhyBf[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function SRFkd(YBIxHpTl,JTxfwL,xpLRACVIJ){nQFwT=YBIxHpTl.split(xpLRACVIJ);bZdGsWP = tCsCYLYWEBjDIOtcVhyBf[13];for(dSiEDSQp=0;dSi" ascii
    $s9  = "function aYjjN(MBGwNx){return new ActiveXObject(MBGwNx);}" fullword ascii
    $s10 = "function glPHRdW() {var aRkk=100000;var rlSxGD = 100;return Math.random()*(aRkk-rlSxGD)+rlSxGD;}" fullword ascii
    $s11 = "function SRFkd(YBIxHpTl,JTxfwL,xpLRACVIJ){nQFwT=YBIxHpTl.split(xpLRACVIJ);bZdGsWP = tCsCYLYWEBjDIOtcVhyBf[13];for(dSiEDSQp=0;dSi" ascii
    $s12 = "function YaQOa(wkeUOiqw,ZomaB,HbxuSxfbbJ){wkeUOiqw.open();wkeUOiqw.type = 1;wkeUOiqw.write(ZomaB);wkeUOiqw.position = 0;wkeUOiqw" ascii
    $s13 = "function YaQOa(wkeUOiqw,ZomaB,HbxuSxfbbJ){wkeUOiqw.open();wkeUOiqw.type = 1;wkeUOiqw.write(ZomaB);wkeUOiqw.position = 0;wkeUOiqw" ascii
    $s14 = "function EnVXGW(MBGwNx){return MBGwNx.ExpandEnvironmentStrings(tCsCYLYWEBjDIOtcVhyBf[10])}" fullword ascii
    $s15 = ".floor(Math.random()*OXfzhWMQ.length));}return flQxM;}" fullword ascii
    $s16 = "function enIwRaAWf(UxZyGTebw,EjscXME,IQLobzGC){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}