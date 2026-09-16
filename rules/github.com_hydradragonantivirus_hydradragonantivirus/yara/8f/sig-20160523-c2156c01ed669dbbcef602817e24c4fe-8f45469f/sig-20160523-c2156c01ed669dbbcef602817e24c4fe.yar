rule sig_20160523_c2156c01ed669dbbcef602817e24c4fe {
  meta:
    description = "datamaliciousorder - file 20160523_c2156c01ed669dbbcef602817e24c4fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "872a12c6c9b8ef8c06c772a576c60afd7f6134ab58e8407d54d414d7b9cdbd75"

  strings:
    $s1  = "function aoACFfgy(mJnWo) {var ybiCxbUv=IWsQMa[2];for(var drpKr=0;drpKr<mJnWo;drpKr++){DhNJP+=ybiCxbUv.charAt(Math.floor(Math.ran" ascii
    $s2  = "function tZlKEZYEfg(JRgnrduM,tsftQqZCdbne) {JRgnrduM.Run(tsftQqZCdbne, 0x1, 0x0);}" fullword ascii
    $s3  = "function aoACFfgy(mJnWo) {var ybiCxbUv=IWsQMa[2];for(var drpKr=0;drpKr<mJnWo;drpKr++){DhNJP+=ybiCxbUv.charAt(Math.floor(Math.ran" ascii
    $s4  = "function YUsrq(pbzvXTSa,jtCpSA,haoLNsraX){VgvFa=pbzvXTSa.split(haoLNsraX);dFhrslN = IWsQMa[13];for(dsQSrigc=0;dsQSrigc<jtCpSA.le" ascii
    $s5  = "function QjLl(KuZQPlb,HeoDdbH) {KuZQPlb.saveToFile(HeoDdbH, 2);}" fullword ascii
    $s6  = "ngth;dsQSrigc++) {dFhrslN+=VgvFa[jtCpSA[dsQSrigc]];}return dFhrslN.substring(3,dFhrslN.length);}" fullword ascii
    $s7  = "function TPYQvLSFP(CqsSnW) {var NVqPdSIAYa=[];CqsSnW.position=NVqPdSIAYa.length*(2814967-768);}" fullword ascii
    $s8  = "function erpzM(fgtUTU){return new ActiveXObject(fgtUTU);}" fullword ascii
    $s9  = "if (eShNIjq==0) break;" fullword ascii
    $s10 = "function jlNac(KURywdLP,TtSSa,uYZpmpdLzB){JwQk(KURywdLP);uqIfyCmQ(KURywdLP);ImMoqmp(KURywdLP,TtSSa);TPYQvLSFP(KURywdLP);QjLl(KUR" ascii
    $s11 = "function PWFWwCn(lLOYg) {lLOYg.close();}" fullword ascii
    $s12 = "function uqIfyCmQ(BTXsPhPpY) {BTXsPhPpY.type=1;}" fullword ascii
    $s13 = "try{eShNIjq=wdahSAxXC(WkRXo[MKvZ], xQEfwGf() + IWsQMa[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function YUsrq(pbzvXTSa,jtCpSA,haoLNsraX){VgvFa=pbzvXTSa.split(haoLNsraX);dFhrslN = IWsQMa[13];for(dsQSrigc=0;dsQSrigc<jtCpSA.le" ascii
    $s15 = "function wdahSAxXC(lDWCfIcxj,nZfHmNf,kVPCfifb){" fullword ascii
    $s16 = "function loYehf(fgtUTU){return fgtUTU.ExpandEnvironmentStrings(IWsQMa[10])}" fullword ascii
    $s17 = "function xQEfwGf() {var zsgz=100000;var cYHlSx = 100;return bcPccth()*(zsgz-cYHlSx)+cYHlSx;}" fullword ascii
    $s18 = "function bcPccth(){return Math.random();}" fullword ascii
    $s19 = "function vLnV(SoghOT,jyZxaDS){AMKl = IWsQMa[11].split(IWsQMa[12]);jyZxaDS.open(AMKl[0]+AMKl[2]+AMKl[3], SoghOT, false);jyZxaDS.s" ascii
    $s20 = "function jlNac(KURywdLP,TtSSa,uYZpmpdLzB){JwQk(KURywdLP);uqIfyCmQ(KURywdLP);ImMoqmp(KURywdLP,TtSSa);TPYQvLSFP(KURywdLP);QjLl(KUR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}