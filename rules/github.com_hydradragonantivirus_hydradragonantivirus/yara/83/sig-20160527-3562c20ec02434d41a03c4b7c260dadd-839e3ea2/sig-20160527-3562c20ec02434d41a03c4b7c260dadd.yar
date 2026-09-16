rule sig_20160527_3562c20ec02434d41a03c4b7c260dadd {
  meta:
    description = "datamaliciousorder - file 20160527_3562c20ec02434d41a03c4b7c260dadd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be08d77f4604bcedebd337604173d389e90d6d36d740488330a0e281c96ec562"

  strings:
    $s1  = "function lXPdJ() {return WScript;}function zTMwn(){return ecreLHvvknRcY.ExpandEnvironmentStrings(tdsyYmQR())}" fullword ascii
    $s2  = "function zAVEOuLYjRFpAMAyVBkBoz(qEtFOWdvdSLRUaSg,prAoZGuoaecnBqHezJAfoqk){return qEtFOWdvdSLRUaSg.charAt(prAoZGuoaecnBqHezJAfoqk" ascii
    $s3  = "function zAVEOuLYjRFpAMAyVBkBoz(qEtFOWdvdSLRUaSg,prAoZGuoaecnBqHezJAfoqk){return qEtFOWdvdSLRUaSg.charAt(prAoZGuoaecnBqHezJAfoqk" ascii
    $s4  = "function jAWuRLrw(){return qJdtD(lWTNiliVsrzfpxMohg[10],[2,4,8,10],lWTNiliVsrzfpxMohg[11]);}" fullword ascii
    $s5  = "3])+String.fromCharCode(92)+lWTNiliVsrzfpxMohg[4],true);" fullword ascii
    $s6  = "function lOanwWHFjc(LfijEDVGSWyNq) {var mEwaNawXtPtODPyTTFtzi = aqitrbPVmLMnDfoqZTTs.join(lWTNiliVsrzfpxMohg[6]);var gXzcXfRxK, " ascii
    $s7  = "function qJdtD(tvJncQmryoaWQS,dapkagkv,gPsRRKz){KeBtOZAK=tvJncQmryoaWQS.split(gPsRRKz);KqlAS = lWTNiliVsrzfpxMohg[14];for(mMqRFg" ascii
    $s8  = "function tdsyYmQR(){return qJdtD(lWTNiliVsrzfpxMohg[8],[1,5,7],lWTNiliVsrzfpxMohg[9]);}" fullword ascii
    $s9  = "var tSWAmeAcLscwf=function(){return new ActiveXObject(lWTNiliVsrzfpxMohg[0]);}();" fullword ascii
    $s10 = "function lOanwWHFjc(LfijEDVGSWyNq) {var mEwaNawXtPtODPyTTFtzi = aqitrbPVmLMnDfoqZTTs.join(lWTNiliVsrzfpxMohg[6]);var gXzcXfRxK, " ascii
    $s11 = ";else if (fZGViTMXMIO == 64) dnNXbhwzbJgvXnLu += ocZDRgM(gXzcXfRxK, NmmGKloadFcVVLeRzesUIPO);else dnNXbhwzbJgvXnLu += ZILJt(gXzc" ascii
    $s12 = "function ZILJt(wBKBlhTGAx,JjUwsgdxrQcWywWZZ,wuAEKyagOxKPMJylASTc){return String.fromCharCode(wBKBlhTGAx,JjUwsgdxrQcWywWZZ,wuAEKy" ascii
    $s13 = "function cJUeTbyCttRAIO(hFvufTiqFG,LtxocopnkqZfjEgdmWnGj){return hFvufTiqFG.indexOf(LtxocopnkqZfjEgdmWnGj);}" fullword ascii
    $s14 = "function FsXsGteAoa(){return qJdtD(lWTNiliVsrzfpxMohg[12],[0,3,6],lWTNiliVsrzfpxMohg[13]);}" fullword ascii
    $s15 = "function HE(uKvWCfRqbETpQUABJ){return String.fromCharCode(uKvWCfRqbETpQUABJ);}" fullword ascii
    $s16 = "XfRxK, NmmGKloadFcVVLeRzesUIPO, EvxqmonObA);} while (NsXCEcKYPnZjNOvsfwCkNvP < LfijEDVGSWyNq.length);return dnNXbhwzbJgvXnLu;}" fullword ascii
    $s17 = "var ecreLHvvknRcY=function(){return lXPdJ().CreateObject(lWTNiliVsrzfpxMohg[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s18 = "function qJdtD(tvJncQmryoaWQS,dapkagkv,gPsRRKz){KeBtOZAK=tvJncQmryoaWQS.split(gPsRRKz);KqlAS = lWTNiliVsrzfpxMohg[14];for(mMqRFg" ascii
    $s19 = "=0;mMqRFg<dapkagkv.length;mMqRFg++) {KqlAS+=KeBtOZAK[dapkagkv[mMqRFg]];}return KqlAS.substring(3,KqlAS.length);}" fullword ascii
    $s20 = "function ZILJt(wBKBlhTGAx,JjUwsgdxrQcWywWZZ,wuAEKyagOxKPMJylASTc){return String.fromCharCode(wBKBlhTGAx,JjUwsgdxrQcWywWZZ,wuAEKy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}