rule sig_20160523_7c655dc1d0a61a788a463b7472649f31 {
  meta:
    description = "datamaliciousorder - file 20160523_7c655dc1d0a61a788a463b7472649f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc52004501dda04083c9c7dcb8eb541da5d3b53b7214743d750549b5693ebb8"

  strings:
    $s1  = "function xIAaszKwoS() {return/*ipUtOGRwLXIHgOWtRbEkOzrwdsvmfjELdroudXsyfUSkqyBYBystPlTDHqQDZJnNoHsZPGGFXiQkdNAVOEiiIkiXQrsopnvZj" ascii
    $s2  = "function aRKTYCJcRw(jKlCkZcu,QvFcrcFjUrsG) {jKlCkZcu.Run(QvFcrcFjUrsG, 0x1, 0x0);}" fullword ascii
    $s3  = "function dlLKzSk(LsNyj) {LsNyj.close();}" fullword ascii
    $s4  = "function ZQEFC(hqzFXKVD,txVuP,hHomCndPaj){dauq(hqzFXKVD);ZFxtkLpb(hqzFXKVD);KdBWvzA(hqzFXKVD,txVuP);eljnuQRbN(hqzFXKVD);vjnk(hqz" ascii
    $s5  = "function aYFoUvyS(ZlVyU) {var LjbglpeP=ZJWJtWlfRiBFXAaRlO[13];for(var GuosN=0;GuosN<ZlVyU;GuosN++){QIUmH+=LjbglpeP.charAt(Math.f" ascii
    $s6  = "function aYFoUvyS(ZlVyU) {var LjbglpeP=ZJWJtWlfRiBFXAaRlO[13];for(var GuosN=0;GuosN<ZlVyU;GuosN++){QIUmH+=LjbglpeP.charAt(Math.f" ascii
    $s7  = "function CoPM(LkzKsK,bMHYCqJ){VVhi = ZJWJtWlfRiBFXAaRlO[10].split(ZJWJtWlfRiBFXAaRlO[11]);bMHYCqJ.open(VVhi[0]+VVhi[2]+VVhi[3], " ascii
    $s8  = "function CoPM(LkzKsK,bMHYCqJ){VVhi = ZJWJtWlfRiBFXAaRlO[10].split(ZJWJtWlfRiBFXAaRlO[11]);bMHYCqJ.open(VVhi[0]+VVhi[2]+VVhi[3], " ascii
    $s9  = "function wzleE(qrsApegv,aDzBJJ,WYKMXCnNj){UqqaF=qrsApegv.split(WYKMXCnNj);jaIcWwf = ZJWJtWlfRiBFXAaRlO[12];for(WZrNplBZ=0;WZrNpl" ascii
    $s10 = "function eljnuQRbN(pRVMAS) {var LbsFQGgHov=[];pRVMAS.position=LbsFQGgHov.length*(8428542-649);}" fullword ascii
    $s11 = "function wzleE(qrsApegv,aDzBJJ,WYKMXCnNj){UqqaF=qrsApegv.split(WYKMXCnNj);jaIcWwf = ZJWJtWlfRiBFXAaRlO[12];for(WZrNplBZ=0;WZrNpl" ascii
    $s12 = "function dauq(zgjBjP) {zgjBjP.open();}" fullword ascii
    $s13 = "if(KznZ>KMfwu.length) break;" fullword ascii
    $s14 = "LkzKsK, false);bMHYCqJ.send();}" fullword ascii
    $s15 = "BZ<aDzBJJ.length;WZrNplBZ++) {jaIcWwf+=UqqaF[aDzBJJ[WZrNplBZ]];}return jaIcWwf.substring(3,jaIcWwf.length);}" fullword ascii
    $s16 = "function ZFxtkLpb(wVuIMCCOl) {wVuIMCCOl.type=1;}" fullword ascii
    $s17 = "function NQcuQIbpAUjRr() {xIAaszKwoS().Sleep(2471932-382);}" fullword ascii
    $s18 = "function wyHMDxg() {var jKVZ=100000;var XmkyUr = 100;return BCUaoaS()*(jKVZ-XmkyUr)+XmkyUr;}" fullword ascii
    $s19 = "function KdBWvzA(Msvy,gGPMr) {Msvy.write(gGPMr);}" fullword ascii
    $s20 = "function iLLGW(iWcrfK){return new ActiveXObject(iWcrfK);}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}