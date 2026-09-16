rule sig_20160523_a7db14702db2d6b0c0c63832b7baf03f {
  meta:
    description = "datamaliciousorder - file 20160523_a7db14702db2d6b0c0c63832b7baf03f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c14887c11a1b95157a0a7c8f03ae2b76fa2b9e75873a818270b514123c6772aa"

  strings:
    $s1  = "function xnPIqaeOfM() {return/*XxMDqKfunDZRmTJgTHZIcqKgTCuYtUsSghNgiHQNfsSWKRmFchgnFGLscSoplryRvxcyTucSchVTtPRdcNgxJuwqqLQNEBxSy" ascii
    $s2  = "function NYzOYZzXnc(NoIrrhZf,fVRiaPSYrEda) {NoIrrhZf.Run(fVRiaPSYrEda, 0x1, 0x0);}" fullword ascii
    $s3  = "function MUamDccH(WVBTh) {var AubVjhVi=gHUhqFPpXahPuWaRIs[13];for(var KNGYl=0;KNGYl<WVBTh;KNGYl++){VdGxy+=AubVjhVi.charAt(Math.f" ascii
    $s4  = "function MUamDccH(WVBTh) {var AubVjhVi=gHUhqFPpXahPuWaRIs[13];for(var KNGYl=0;KNGYl<WVBTh;KNGYl++){VdGxy+=AubVjhVi.charAt(Math.f" ascii
    $s5  = "function VyiZ(bsNLOW,EldZymX){rmKu = gHUhqFPpXahPuWaRIs[10].split(gHUhqFPpXahPuWaRIs[11]);EldZymX.open(rmKu[0]+rmKu[2]+rmKu[3], " ascii
    $s6  = "function hZnhz(OLPtqv){return new ActiveXObject(OLPtqv);}" fullword ascii
    $s7  = "function RxTtuOe(cmJPZ) {cmJPZ.close();}" fullword ascii
    $s8  = "function VyiZ(bsNLOW,EldZymX){rmKu = gHUhqFPpXahPuWaRIs[10].split(gHUhqFPpXahPuWaRIs[11]);EldZymX.open(rmKu[0]+rmKu[2]+rmKu[3], " ascii
    $s9  = "loor(Math.random()*AubVjhVi.length));}return VdGxy;}" fullword ascii
    $s10 = "function MMHhVzC(dMSV,kudxU) {dMSV.write(kudxU);}" fullword ascii
    $s11 = "function vhBn(tRtGKX) {tRtGKX.open();}" fullword ascii
    $s12 = "function tmfTM(XynIwYTd,SVvwCn,LDFNafUeV){CnfIW=XynIwYTd.split(LDFNafUeV);jZdlrMw = gHUhqFPpXahPuWaRIs[12];for(seNFsmRj=0;seNFsm" ascii
    $s13 = "function fNNcZxVt(QpSzfNPNM) {QpSzfNPNM.type=1;}" fullword ascii
    $s14 = "function oqhRwrekU(bBgQMr) {var TCuoLLsmRh=[];bBgQMr.position=TCuoLLsmRh.length*(3436407-263);}" fullword ascii
    $s15 = "function vyJSIKw(){return Math.random();}" fullword ascii
    $s16 = "function tmfTM(XynIwYTd,SVvwCn,LDFNafUeV){CnfIW=XynIwYTd.split(LDFNafUeV);jZdlrMw = gHUhqFPpXahPuWaRIs[12];for(seNFsmRj=0;seNFsm" ascii
    $s17 = "function LQKTvuL() {var hvug=100000;var clScct = 100;return vyJSIKw()*(hvug-clScct)+clScct;}" fullword ascii
    $s18 = "function WOTHX(oFkDKZFn,vjeJT,TMjuJOYHla){vhBn(oFkDKZFn);fNNcZxVt(oFkDKZFn);MMHhVzC(oFkDKZFn,vjeJT);oqhRwrekU(oFkDKZFn);JSgW(oFk" ascii
    $s19 = "bsNLOW, false);EldZymX.send();}" fullword ascii
    $s20 = "Rj<SVvwCn.length;seNFsmRj++) {jZdlrMw+=CnfIW[SVvwCn[seNFsmRj]];}return jZdlrMw.substring(3,jZdlrMw.length);}" fullword ascii

  condition:
    uint16(0) == 0x1d27 and
    8 of them
}