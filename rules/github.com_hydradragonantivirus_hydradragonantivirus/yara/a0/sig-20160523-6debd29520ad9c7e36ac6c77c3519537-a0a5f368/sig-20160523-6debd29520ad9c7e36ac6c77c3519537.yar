rule sig_20160523_6debd29520ad9c7e36ac6c77c3519537 {
  meta:
    description = "datamaliciousorder - file 20160523_6debd29520ad9c7e36ac6c77c3519537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca592ce08067ebce56222cd7a034de99421e5a4fb66ad72d4b2662689a0b57e5"

  strings:
    $s1  = "function ZCioJZUfVf() {return/*BVfAiBcwBEJiiTguuOAqeOCUgNTRmNKYHiCjKcsTflnjhlZChBjqRlELFyJNKfpOaudUBBmhvhBGqIGqoBjgJQMAzhowALnYC" ascii
    $s2  = "function JbWxKNQjBO(VZoHbBmr,hsOhjhXfuqIH) {VZoHbBmr.Run(hsOhjhXfuqIH, 0x1, 0x0);}" fullword ascii
    $s3  = "function qtTujlba(CEPTM) {var cHaMAyRu=VXmQpImCmJ[13];for(var VJjIB=0;VJjIB<CEPTM;VJjIB++){GXvEz+=cHaMAyRu.charAt(Math.floor(Mat" ascii
    $s4  = "function qtTujlba(CEPTM) {var cHaMAyRu=VXmQpImCmJ[13];for(var VJjIB=0;VJjIB<CEPTM;VJjIB++){GXvEz+=cHaMAyRu.charAt(Math.floor(Mat" ascii
    $s5  = "function xYKyE(BqUEfHvy,ilcMhq,KeYDIpdZD){WoaUf=BqUEfHvy.split(KeYDIpdZD);UIqYnLw = VXmQpImCmJ[12];for(pInLqiLg=0;pInLqiLg<ilcMh" ascii
    $s6  = "function xYKyE(BqUEfHvy,ilcMhq,KeYDIpdZD){WoaUf=BqUEfHvy.split(KeYDIpdZD);UIqYnLw = VXmQpImCmJ[12];for(pInLqiLg=0;pInLqiLg<ilcMh" ascii
    $s7  = "function sUxqmhnC(hrrAznBtX) {hrrAznBtX.type=1;}" fullword ascii
    $s8  = "function XpznsgqDW(CYQvus) {var PNHyZvGDtH=[];CYQvus.position=PNHyZvGDtH.length*(3147281-755);}" fullword ascii
    $s9  = "function AWdn(WBzWpK,TXafcVP){PTNv = VXmQpImCmJ[10].split(VXmQpImCmJ[11]);TXafcVP.open(PTNv[0]+PTNv[2]+PTNv[3], WBzWpK, false);T" ascii
    $s10 = "function AWdn(WBzWpK,TXafcVP){PTNv = VXmQpImCmJ[10].split(VXmQpImCmJ[11]);TXafcVP.open(PTNv[0]+PTNv[2]+PTNv[3], WBzWpK, false);T" ascii
    $s11 = "function VnioV(jhQZGIkS,RrUEt,LkQGicyTtf){uibj(jhQZGIkS);sUxqmhnC(jhQZGIkS);cDBEtpa(jhQZGIkS,RrUEt);XpznsgqDW(jhQZGIkS);zraA(jhQ" ascii
    $s12 = "AWdn(lPCyPiSNR,vIRiD);" fullword ascii
    $s13 = "h.random()*cHaMAyRu.length));}return GXvEz;}" fullword ascii
    $s14 = "function RkFCQuSDCtxKF() {ZCioJZUfVf().Sleep(2288801-443);}" fullword ascii
    $s15 = "q.length;pInLqiLg++) {UIqYnLw+=WoaUf[ilcMhq[pInLqiLg]];}return UIqYnLw.substring(3,UIqYnLw.length);}" fullword ascii
    $s16 = "if(HhWl>AHfIQ.length) break;" fullword ascii
    $s17 = "function Kjkjnpf() {var iuEk=100000;var LWgtCw = 100;return ueuethG()*(iuEk-LWgtCw)+LWgtCw;}" fullword ascii
    $s18 = "function cDBEtpa(MtoM,umgXg) {MtoM.write(umgXg);}" fullword ascii
    $s19 = "function zraA(UBmGlII,mypCpYw) {UBmGlII.saveToFile(mypCpYw, 2);}" fullword ascii
    $s20 = "function sOtCC(gWGHEw){return new ActiveXObject(gWGHEw);}" fullword ascii

  condition:
    uint16(0) == 0x0c27 and
    8 of them
}