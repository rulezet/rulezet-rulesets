rule sig_20160523_a373f72cbb8b0168b98727faf8f1def8 {
  meta:
    description = "datamaliciousorder - file 20160523_a373f72cbb8b0168b98727faf8f1def8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78f086c73a3931444b3b2a7e58f379268b4b638a55ed9d564c6af39c40c2ad03"

  strings:
    $s1  = "function IqtDcxpzFf() {return/*aPopiNlLXAtXhfeEaIuWhtGagtmjbsOzcVwiYonQJPMnLzuyWiuiivKhlcSvPqWrNbrcGFSdlNOzORLOjNCuMkfpjuQKkUIXt" ascii
    $s2  = "function WHcKYwVqQV(hBItHYna,fZwmMbwdYnLO) {hBItHYna.Run(fZwmMbwdYnLO, 0x1, 0x0);}" fullword ascii
    $s3  = "function aoWVBExM(cTPgw) {var wIVebuvu=TJMjscyAbqlqTBOucMCUvQ[13];for(var bafOP=0;bafOP<cTPgw;bafOP++){ITtxc+=wIVebuvu.charAt(Ma" ascii
    $s4  = "function aoWVBExM(cTPgw) {var wIVebuvu=TJMjscyAbqlqTBOucMCUvQ[13];for(var bafOP=0;bafOP<cTPgw;bafOP++){ITtxc+=wIVebuvu.charAt(Ma" ascii
    $s5  = "function nBLLLmJ(){return Math.random();}" fullword ascii
    $s6  = "function jgqhv(ecnMsGau,HmgWB,StlptclgGn){aNCP(ecnMsGau);wYQmBeuB(ecnMsGau);mRPTsFX(ecnMsGau,HmgWB);tdRfBYTQH(ecnMsGau);Iwpm(ecn" ascii
    $s7  = "function xpYCW(xjGsniPd,BwRGWp,QKMXCWWOb){Mpbwo=xjGsniPd.split(QKMXCWWOb);NmDklLb = TJMjscyAbqlqTBOucMCUvQ[12];for(CXibclWP=0;CX" ascii
    $s8  = "function mRPTsFX(EpXj,ukTcR) {EpXj.write(ukTcR);}" fullword ascii
    $s9  = "function jgqhv(ecnMsGau,HmgWB,StlptclgGn){aNCP(ecnMsGau);wYQmBeuB(ecnMsGau);mRPTsFX(ecnMsGau,HmgWB);tdRfBYTQH(ecnMsGau);Iwpm(ecn" ascii
    $s10 = "ibclWP<BwRGWp.length;CXibclWP++) {NmDklLb+=Mpbwo[BwRGWp[CXibclWP]];}return NmDklLb.substring(3,NmDklLb.length);}" fullword ascii
    $s11 = "function VQdqr(nmosWb){return new ActiveXObject(nmosWb);}" fullword ascii
    $s12 = "function wYQmBeuB(BWgsTkkFM) {BWgsTkkFM.type=1;}" fullword ascii
    $s13 = "function arAizN(nmosWb){return nmosWb.ExpandEnvironmentStrings(TJMjscyAbqlqTBOucMCUvQ[9])}" fullword ascii
    $s14 = "function cLkRPoflygcMv() {IqtDcxpzFf().Sleep(2395465-965);}" fullword ascii
    $s15 = "function Iwpm(uUejUZT,JzokicU) {uUejUZT.saveToFile(JzokicU, 2);}" fullword ascii
    $s16 = "th.floor(Math.random()*wIVebuvu.length));}return ITtxc;}" fullword ascii
    $s17 = "function tdRfBYTQH(ViHZyp) {var pFIcpVZCet=[];ViHZyp.position=pFIcpVZCet.length*(1616973-144);}" fullword ascii
    $s18 = "function IqtDcxpzFf() {return/*aPopiNlLXAtXhfeEaIuWhtGagtmjbsOzcVwiYonQJPMnLzuyWiuiivKhlcSvPqWrNbrcGFSdlNOzORLOjNCuMkfpjuQKkUIXt" ascii
    $s19 = "function xpYCW(xjGsniPd,BwRGWp,QKMXCWWOb){Mpbwo=xjGsniPd.split(QKMXCWWOb);NmDklLb = TJMjscyAbqlqTBOucMCUvQ[12];for(CXibclWP=0;CX" ascii
    $s20 = "function eAWg(WtVOJr,gpDUjJn){xgKC = TJMjscyAbqlqTBOucMCUvQ[10].split(TJMjscyAbqlqTBOucMCUvQ[11]);gpDUjJn.open(xgKC[0]+xgKC[2]+x" ascii

  condition:
    uint16(0) == 0x0527 and
    8 of them
}