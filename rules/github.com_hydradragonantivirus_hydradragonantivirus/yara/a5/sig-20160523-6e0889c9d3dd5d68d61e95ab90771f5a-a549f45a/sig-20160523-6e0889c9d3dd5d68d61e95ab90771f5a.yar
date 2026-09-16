rule sig_20160523_6e0889c9d3dd5d68d61e95ab90771f5a {
  meta:
    description = "datamaliciousorder - file 20160523_6e0889c9d3dd5d68d61e95ab90771f5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b586553834f805baca86c0471324683d0db80d0554e7da1cf8e6583ed6d53cff"

  strings:
    $s1  = "function GjrGNRDUmT(SFTqQzcD,BNEHFgRafRGG) {SFTqQzcD.Run(BNEHFgRafRGG, 0x1, 0x0);}" fullword ascii
    $s2  = "function jNwOYBIc(XBuVD) {var RPkRdHnj=XKAgXxwaUd[13];for(var pfWEg=0;pfWEg<XBuVD;pfWEg++){WDAHs+=RPkRdHnj.charAt(Math.floor(Mat" ascii
    $s3  = "function jNwOYBIc(XBuVD) {var RPkRdHnj=XKAgXxwaUd[13];for(var pfWEg=0;pfWEg<XBuVD;pfWEg++){WDAHs+=RPkRdHnj.charAt(Math.floor(Mat" ascii
    $s4  = "h.random()*RPkRdHnj.length));}return WDAHs;}" fullword ascii
    $s5  = "if(FGTu>WgFZS.length) break;" fullword ascii
    $s6  = "function WDlpt(TssAUyzP,MPDlZ,bVlNvsOGHo){FUQi(TssAUyzP);txSpHpPy(TssAUyzP);OBlqPdn(TssAUyzP,MPDlZ);cQSsNwnvQ(TssAUyzP);LBhE(Tss" ascii
    $s7  = "function qKfNepo(){return Math.random();}" fullword ascii
    $s8  = "function GZCyhLs() {var XAOa=100000;var cfFGYM = 100;return qKfNepo()*(XAOa-cfFGYM)+cfFGYM;}" fullword ascii
    $s9  = "x.length;GVfADfHR++) {LBCpCCT+=SLnFq[lnSRAx[GVfADfHR]];}return LBCpCCT.substring(3,LBCpCCT.length);}" fullword ascii
    $s10 = "function oyGTzLk(ezyeF) {ezyeF.close();}" fullword ascii
    $s11 = "function tJYz(XAdsam,kLAwcVV){kSOj = XKAgXxwaUd[10].split(XKAgXxwaUd[11]);kLAwcVV.open(kSOj[0]+kSOj[2]+kSOj[3], XAdsam, false);k" ascii
    $s12 = "function xtsAJ(TcPsaHAO,lnSRAx,DSqsRIGCv){SLnFq=TcPsaHAO.split(DSqsRIGCv);LBCpCCT = XKAgXxwaUd[12];for(GVfADfHR=0;GVfADfHR<lnSRA" ascii
    $s13 = "function tuLOy(EHFMgm){return new ActiveXObject(EHFMgm);}" fullword ascii
    $s14 = "function OBlqPdn(tpyq,Vlsfp) {tpyq.write(Vlsfp);}" fullword ascii
    $s15 = "function FUQi(FYcMqb) {FYcMqb.open();}" fullword ascii
    $s16 = "function cQSsNwnvQ(pDsiay) {var AqJlLkUzqp=[];pDsiay.position=AqJlLkUzqp.length*(4079272-603);}" fullword ascii
    $s17 = "function WDlpt(TssAUyzP,MPDlZ,bVlNvsOGHo){FUQi(TssAUyzP);txSpHpPy(TssAUyzP);OBlqPdn(TssAUyzP,MPDlZ);cQSsNwnvQ(TssAUyzP);LBhE(Tss" ascii
    $s18 = "function LBhE(OdDBhpw,fwWcNLl) {OdDBhpw.saveToFile(fwWcNLl, 2);}" fullword ascii
    $s19 = "function tJYz(XAdsam,kLAwcVV){kSOj = XKAgXxwaUd[10].split(XKAgXxwaUd[11]);kLAwcVV.open(kSOj[0]+kSOj[2]+kSOj[3], XAdsam, false);k" ascii
    $s20 = "function xtsAJ(TcPsaHAO,lnSRAx,DSqsRIGCv){SLnFq=TcPsaHAO.split(DSqsRIGCv);LBCpCCT = XKAgXxwaUd[12];for(GVfADfHR=0;GVfADfHR<lnSRA" ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}