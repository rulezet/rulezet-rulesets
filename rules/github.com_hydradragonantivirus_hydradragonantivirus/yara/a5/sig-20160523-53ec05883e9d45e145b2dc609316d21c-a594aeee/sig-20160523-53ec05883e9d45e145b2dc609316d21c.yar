rule sig_20160523_53ec05883e9d45e145b2dc609316d21c {
  meta:
    description = "datamaliciousorder - file 20160523_53ec05883e9d45e145b2dc609316d21c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e62e41730868a3431c9ae029f48bd4e4b5dbd3dacf4bc0d93712b58d141f80d"

  strings:
    $s1  = "function QOoTsMfl(zzCnH) {var DauJeVJV=lJbwg[13];for(var XdywW=0;XdywW<zzCnH;XdywW++){JWLnS+=DauJeVJV.charAt(Math.floor(Math.ran" ascii
    $s2  = "function UZxFLRtvNW() {return/*xnaLDQWUbhiAjIqHGbXKzWLTZjQmzbFOtdDOmLDXixAWXfrhjmuRCMvuJSOGVRveTsjlPIUqfaRgqcZiMOXteVzrAXPHZfIKK" ascii
    $s3  = "function PPjevnQyZX(hbKYLNEo,cSNmkLGjnOnm) {hbKYLNEo.Run(cSNmkLGjnOnm, 0x1, 0x0);}" fullword ascii
    $s4  = "function QOoTsMfl(zzCnH) {var DauJeVJV=lJbwg[13];for(var XdywW=0;XdywW<zzCnH;XdywW++){JWLnS+=DauJeVJV.charAt(Math.floor(Math.ran" ascii
    $s5  = "function FlKlq(XxClAWXQ,vaXOop,HfGwqdZdw){VTkyW=XxClAWXQ.split(HfGwqdZdw);jpFVBBT = lJbwg[12];for(DexYZsWc=0;DexYZsWc<vaXOop.len" ascii
    $s6  = "function DHgB(mwlpws,cFrAUsz){bDcg = lJbwg[10].split(lJbwg[11]);cFrAUsz.open(bDcg[0]+bDcg[2]+bDcg[3], mwlpws, false);cFrAUsz.sen" ascii
    $s7  = "function EQMmd(cRqBND){return new ActiveXObject(cRqBND);}" fullword ascii
    $s8  = "function UZxFLRtvNW() {return/*xnaLDQWUbhiAjIqHGbXKzWLTZjQmzbFOtdDOmLDXixAWXfrhjmuRCMvuJSOGVRveTsjlPIUqfaRgqcZiMOXteVzrAXPHZfIKK" ascii
    $s9  = "function LgNr(DjZpQN) {DjZpQN.open();}" fullword ascii
    $s10 = "function FlKlq(XxClAWXQ,vaXOop,HfGwqdZdw){VTkyW=XxClAWXQ.split(HfGwqdZdw);jpFVBBT = lJbwg[12];for(DexYZsWc=0;DexYZsWc<vaXOop.len" ascii
    $s11 = "function vLeSlKn(){return Math.random();}" fullword ascii
    $s12 = "dom()*DauJeVJV.length));}return JWLnS;}" fullword ascii
    $s13 = "function QSDt(ghElxUL,NbZtbqo) {ghElxUL.saveToFile(NbZtbqo, 2);}" fullword ascii
    $s14 = "function YPpBPeJ() {var QOVR=100000;var HwURbk = 100;return vLeSlKn()*(QOVR-HwURbk)+HwURbk;}" fullword ascii
    $s15 = "function ktSPltNAH(apJhCO) {var URqltTXcsz=[];apJhCO.position=URqltTXcsz.length*(4242612-302);}" fullword ascii
    $s16 = "if(WAFu>ayiRb.length) break;" fullword ascii
    $s17 = "function kBVfP(DoUKgADN,TwvPr,gXQPgQQIIu){LgNr(DoUKgADN);rblKtZJc(DoUKgADN);DTFjsSt(DoUKgADN,TwvPr);ktSPltNAH(DoUKgADN);QSDt(DoU" ascii
    $s18 = "function KOtIAzwtGUPXm() {UZxFLRtvNW().Sleep(2442376-190);}" fullword ascii
    $s19 = "function rblKtZJc(TtgPqfAOF) {TtgPqfAOF.type=1;}" fullword ascii
    $s20 = "function WNhkwN(cRqBND){return cRqBND.ExpandEnvironmentStrings(lJbwg[9])}" fullword ascii

  condition:
    uint16(0) == 0x0127 and
    8 of them
}