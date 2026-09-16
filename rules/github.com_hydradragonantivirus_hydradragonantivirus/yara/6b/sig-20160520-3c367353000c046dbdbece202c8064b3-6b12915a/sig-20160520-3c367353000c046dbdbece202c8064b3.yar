rule sig_20160520_3c367353000c046dbdbece202c8064b3 {
  meta:
    description = "datamaliciousorder - file 20160520_3c367353000c046dbdbece202c8064b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "212f403e65d998d2d9c1780ec6981b2a918548c81dedf419a6b86130add7127c"

  strings:
    $s1  = "function nIbhmaGZ(SQfTX) {var ccyUkDbA=GEDfzfTOjdOV[2];for(var lmnhE=0;lmnhE<SQfTX;lmnhE++){jtHnX+=ccyUkDbA.charAt(Math.floor(Ma" ascii
    $s2  = "function nIbhmaGZ(SQfTX) {var ccyUkDbA=GEDfzfTOjdOV[2];for(var lmnhE=0;lmnhE<SQfTX;lmnhE++){jtHnX+=ccyUkDbA.charAt(Math.floor(Ma" ascii
    $s3  = "function CEUBb(mpybDnlA,kBfYk,patjqljlOG){mpybDnlA.open();mpybDnlA.type = 1;mpybDnlA.write(kBfYk);mpybDnlA.position = 0;mpybDnlA" ascii
    $s4  = "function CEUBb(mpybDnlA,kBfYk,patjqljlOG){mpybDnlA.open();mpybDnlA.type = 1;mpybDnlA.write(kBfYk);mpybDnlA.position = 0;mpybDnlA" ascii
    $s5  = "IAO.length;CjpKGAug++) {TpResPc+=OEbfq[zUEIAO[CjpKGAug]];}return TpResPc.substring(3,TpResPc.length);}" fullword ascii
    $s6  = "try{HgUXLoqSE(MbEdA[FLGU], UzffYpn() + GEDfzfTOjdOV[9], 1)}catch(e){}; " fullword ascii
    $s7  = "function ByMGT(JLsTtDfs,zUEIAO,bIuRgIHhf){OEbfq=JLsTtDfs.split(bIuRgIHhf);TpResPc = GEDfzfTOjdOV[13];for(CjpKGAug=0;CjpKGAug<zUE" ascii
    $s8  = "function zFctx(mZvPfD){return new ActiveXObject(mZvPfD);}" fullword ascii
    $s9  = "th.random()*ccyUkDbA.length));}return jtHnX;}" fullword ascii
    $s10 = "function kuhtzD(mZvPfD){return mZvPfD.ExpandEnvironmentStrings(GEDfzfTOjdOV[10])}" fullword ascii
    $s11 = "function UzffYpn() {var fXua=100000;var GeFqmd = 100;return Math.random()*(fXua-GeFqmd)+GeFqmd;}" fullword ascii
    $s12 = "function sWvB(tuwQkl,CQqyasI){NAPM = GEDfzfTOjdOV[11].split(GEDfzfTOjdOV[12]);CQqyasI.open(NAPM[0]+NAPM[2]+NAPM[3], tuwQkl, fals" ascii
    $s13 = "function ByMGT(JLsTtDfs,zUEIAO,bIuRgIHhf){OEbfq=JLsTtDfs.split(bIuRgIHhf);TpResPc = GEDfzfTOjdOV[13];for(CjpKGAug=0;CjpKGAug<zUE" ascii
    $s14 = "function HgUXLoqSE(JVYWJjuYe,cNwobfB,dcdYRGLa){" fullword ascii
    $s15 = "function sWvB(tuwQkl,CQqyasI){NAPM = GEDfzfTOjdOV[11].split(GEDfzfTOjdOV[12]);CQqyasI.open(NAPM[0]+NAPM[2]+NAPM[3], tuwQkl, fals" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}