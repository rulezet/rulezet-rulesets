rule sig_20160523_7a37d2add603932d291513214b83d72d {
  meta:
    description = "datamaliciousorder - file 20160523_7a37d2add603932d291513214b83d72d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9295e48df0a8c4c90f801dec0230f592b320d36c147f93db81fe6b370880f4a5"

  strings:
    $s1  = "function cPsvsooBsU(zvclIsUu,cmTXsuwbPIDk) {zvclIsUu.Run(cmTXsuwbPIDk, 0x1, 0x0);}" fullword ascii
    $s2  = "function tNvdRsoj(DmqnK) {var HqpQoILZ=uwoZDTMNIBbAPtarZEYd[2];for(var tjAQG=0;tjAQG<DmqnK;tjAQG++){mivoH+=HqpQoILZ.charAt(Math." ascii
    $s3  = "function tNvdRsoj(DmqnK) {var HqpQoILZ=uwoZDTMNIBbAPtarZEYd[2];for(var tjAQG=0;tjAQG<DmqnK;tjAQG++){mivoH+=HqpQoILZ.charAt(Math." ascii
    $s4  = "function kBKdRsJT(sMFtMplUy) {sMFtMplUy.type=1;}" fullword ascii
    $s5  = "function fNKk(PrfuaVw,DyQjPsV) {PrfuaVw.saveToFile(DyQjPsV, 2);}" fullword ascii
    $s6  = "function TygVS(YOjHodWp,ETfwG,zkhGPhaogx){ONqL(YOjHodWp);kBKdRsJT(YOjHodWp);fKnBNPS(YOjHodWp,ETfwG);ovPKohIqE(YOjHodWp);fNKk(YOj" ascii
    $s7  = "if (KGpvYZK==0) break;" fullword ascii
    $s8  = "function SIGrQ(iULLHvwb,jtrKuz,NltaCCJHb){EiSKR=iULLHvwb.split(NltaCCJHb);QfymoCi = uwoZDTMNIBbAPtarZEYd[13];for(hwFeamFb=0;hwFe" ascii
    $s9  = "function ovPKohIqE(CXEQua) {var WcSJrTJqnu=[];CXEQua.position=WcSJrTJqnu.length*(6194415-308);}" fullword ascii
    $s10 = "function gVCwlFb(){return Math.random();}" fullword ascii
    $s11 = "try{KGpvYZK=sLfwrhmZb(ZueDK[meSN], caxatnd() + uwoZDTMNIBbAPtarZEYd[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function IjVAP(wmaGuC){return new ActiveXObject(wmaGuC);}" fullword ascii
    $s13 = "function SIGrQ(iULLHvwb,jtrKuz,NltaCCJHb){EiSKR=iULLHvwb.split(NltaCCJHb);QfymoCi = uwoZDTMNIBbAPtarZEYd[13];for(hwFeamFb=0;hwFe" ascii
    $s14 = "function pKwAmsU(zasxi) {zasxi.close();}" fullword ascii
    $s15 = "function EFjceK(wmaGuC){return wmaGuC.ExpandEnvironmentStrings(uwoZDTMNIBbAPtarZEYd[10])}" fullword ascii
    $s16 = "function gRqd(fZLxaY,iEyAaWC){PfyS = uwoZDTMNIBbAPtarZEYd[11].split(uwoZDTMNIBbAPtarZEYd[12]);iEyAaWC.open(PfyS[0]+PfyS[2]+PfyS[" ascii
    $s17 = "function TygVS(YOjHodWp,ETfwG,zkhGPhaogx){ONqL(YOjHodWp);kBKdRsJT(YOjHodWp);fKnBNPS(YOjHodWp,ETfwG);ovPKohIqE(YOjHodWp);fNKk(YOj" ascii
    $s18 = "3], fZLxaY, false);iEyAaWC.send();}" fullword ascii
    $s19 = "amFb<jtrKuz.length;hwFeamFb++) {QfymoCi+=EiSKR[jtrKuz[hwFeamFb]];}return QfymoCi.substring(3,QfymoCi.length);}" fullword ascii
    $s20 = "floor(Math.random()*HqpQoILZ.length));}return mivoH;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}