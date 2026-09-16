rule sig_20160520_719ddb09c935230e6d71f0593aaae971 {
  meta:
    description = "datamaliciousorder - file 20160520_719ddb09c935230e6d71f0593aaae971.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2844d67b0a914ebe2dfbf34e70036acf8721dfa18b89fa5fecf85d8ae4d8fb6"

  strings:
    $s1  = "function bpGjXBpD(Nyekq) {var fGQYUXHB=pQDzBnHxWJHFxVBkBHO[2];for(var PLttq=0;PLttq<Nyekq;PLttq++){Ynrtr+=fGQYUXHB.charAt(Math.f" ascii
    $s2  = "function bpGjXBpD(Nyekq) {var fGQYUXHB=pQDzBnHxWJHFxVBkBHO[2];for(var PLttq=0;PLttq<Nyekq;PLttq++){Ynrtr+=fGQYUXHB.charAt(Math.f" ascii
    $s3  = "function pfrJE(ktWPbCwL,CxWMki,GJZpmUsWa){fmqOS=ktWPbCwL.split(GJZpmUsWa);IVoeBZA = pQDzBnHxWJHFxVBkBHO[13];for(mpJFbnFp=0;mpJFb" ascii
    $s4  = "function uTNcp(uOFRuJ){return new ActiveXObject(uOFRuJ);}" fullword ascii
    $s5  = "function JioA(SXdndr,kXQwWxd){PXfo = pQDzBnHxWJHFxVBkBHO[11].split(pQDzBnHxWJHFxVBkBHO[12]);kXQwWxd.open(PXfo[0]+PXfo[2]+PXfo[3]" ascii
    $s6  = "function QyCmvRfxc(JfiutZwKM,NSJgTBC,tpdaRACq){" fullword ascii
    $s7  = "function VAvrN(MQZuUcJP,FROuW,tgjzvcGtgu){MQZuUcJP.open();MQZuUcJP.type = 1;MQZuUcJP.write(FROuW);MQZuUcJP.position = 0;MQZuUcJP" ascii
    $s8  = "function VAvrN(MQZuUcJP,FROuW,tgjzvcGtgu){MQZuUcJP.open();MQZuUcJP.type = 1;MQZuUcJP.write(FROuW);MQZuUcJP.position = 0;MQZuUcJP" ascii
    $s9  = ", SXdndr, false);kXQwWxd.send();}" fullword ascii
    $s10 = "function iUQdxN(uOFRuJ){return uOFRuJ.ExpandEnvironmentStrings(pQDzBnHxWJHFxVBkBHO[10])}" fullword ascii
    $s11 = "function gWITxKL() {var XXZF=100000;var PSIqZS = 100;return Math.random()*(XXZF-PSIqZS)+PSIqZS;}" fullword ascii
    $s12 = "function pfrJE(ktWPbCwL,CxWMki,GJZpmUsWa){fmqOS=ktWPbCwL.split(GJZpmUsWa);IVoeBZA = pQDzBnHxWJHFxVBkBHO[13];for(mpJFbnFp=0;mpJFb" ascii
    $s13 = "try{QyCmvRfxc(elrZx[OrAp], gWITxKL() + pQDzBnHxWJHFxVBkBHO[9], 1)}catch(e){}; " fullword ascii
    $s14 = "nFp<CxWMki.length;mpJFbnFp++) {IVoeBZA+=fmqOS[CxWMki[mpJFbnFp]];}return IVoeBZA.substring(3,IVoeBZA.length);}" fullword ascii
    $s15 = "function JioA(SXdndr,kXQwWxd){PXfo = pQDzBnHxWJHFxVBkBHO[11].split(pQDzBnHxWJHFxVBkBHO[12]);kXQwWxd.open(PXfo[0]+PXfo[2]+PXfo[3]" ascii
    $s16 = "loor(Math.random()*fGQYUXHB.length));}return Ynrtr;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}