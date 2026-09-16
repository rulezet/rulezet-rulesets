rule sig_20160523_59cdf5e4f23b06698d8a272676e72df8 {
  meta:
    description = "datamaliciousorder - file 20160523_59cdf5e4f23b06698d8a272676e72df8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6b8e966f81e0b5b74c4f6036f40a0fcd16e9549ba46dc30ad8d851938bda4a9"

  strings:
    $s1  = "function SRkApzlDva(uoCSRUCb,ggNZribJfNKF) {uoCSRUCb.Run(ggNZribJfNKF, 0x1, 0x0);}" fullword ascii
    $s2  = "function gkKukvnl(wwaZO) {var TJaKRAik=wzCUqf[13];for(var TjNMg=0;TjNMg<wwaZO;TjNMg++){WIniy+=TJaKRAik.charAt(Math.floor(Math.ra" ascii
    $s3  = "function gkKukvnl(wwaZO) {var TJaKRAik=wzCUqf[13];for(var TjNMg=0;TjNMg<wwaZO;TjNMg++){WIniy+=TJaKRAik.charAt(Math.floor(Math.ra" ascii
    $s4  = "ngth;IgoxVrGD++) {RSbFDxq+=RvfsP[hlPbCR[IgoxVrGD]];}return RSbFDxq.substring(3,RSbFDxq.length);}" fullword ascii
    $s5  = "function ccTko(oRphSARI,qEinP,qeVUuYeIcH){OzUz(oRphSARI);VMgbvOoJ(oRphSARI);GnjzKuE(oRphSARI,qEinP);XADvFelRc(oRphSARI);IWUt(oRp" ascii
    $s6  = "function OLaz(wiyqaE,iyadqPt){kHID = wzCUqf[10].split(wzCUqf[11]);iyadqPt.open(kHID[0]+kHID[2]+kHID[3], wiyqaE, false);iyadqPt.s" ascii
    $s7  = "if(xvtu>qHjGN.length) break;" fullword ascii
    $s8  = "ndom()*TJaKRAik.length));}return WIniy;}" fullword ascii
    $s9  = "function OzUz(KukPXa) {KukPXa.open();}" fullword ascii
    $s10 = "function aLHag(XyCBNPmc,hlPbCR,wqXmRmQBo){RvfsP=XyCBNPmc.split(wqXmRmQBo);RSbFDxq = wzCUqf[12];for(IgoxVrGD=0;IgoxVrGD<hlPbCR.le" ascii
    $s11 = "function hAhFZIb() {var CBes=100000;var QHMKgH = 100;return wKrdejQ()*(CBes-QHMKgH)+QHMKgH;}" fullword ascii
    $s12 = "function wKrdejQ(){return Math.random();}" fullword ascii
    $s13 = "function GnjzKuE(ALzl,SiIqt) {ALzl.write(SiIqt);}" fullword ascii
    $s14 = "function ccTko(oRphSARI,qEinP,qeVUuYeIcH){OzUz(oRphSARI);VMgbvOoJ(oRphSARI);GnjzKuE(oRphSARI,qEinP);XADvFelRc(oRphSARI);IWUt(oRp" ascii
    $s15 = "function BjaDn(QQvbQT){return new ActiveXObject(QQvbQT);}" fullword ascii
    $s16 = "function VMgbvOoJ(BTcKFzApy) {BTcKFzApy.type=1;}" fullword ascii
    $s17 = "function iIfOAz(QQvbQT){return QQvbQT.ExpandEnvironmentStrings(wzCUqf[9])}" fullword ascii
    $s18 = "function IXJIhOO(bneNu) {bneNu.close();}" fullword ascii
    $s19 = "function IWUt(NzkcnZP,poGAfuf) {NzkcnZP.saveToFile(poGAfuf, 2);}" fullword ascii
    $s20 = "function OLaz(wiyqaE,iyadqPt){kHID = wzCUqf[10].split(wzCUqf[11]);iyadqPt.open(kHID[0]+kHID[2]+kHID[3], wiyqaE, false);iyadqPt.s" ascii

  condition:
    uint16(0) == 0x0f27 and
    8 of them
}