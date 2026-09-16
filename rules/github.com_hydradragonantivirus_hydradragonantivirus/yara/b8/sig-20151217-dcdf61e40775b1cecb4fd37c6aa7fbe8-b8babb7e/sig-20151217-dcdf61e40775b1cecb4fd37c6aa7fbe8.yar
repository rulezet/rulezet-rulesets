rule sig_20151217_dcdf61e40775b1cecb4fd37c6aa7fbe8 {
  meta:
    description = "datamaliciousorder - file 20151217_dcdf61e40775b1cecb4fd37c6aa7fbe8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c62ead15a77400cc079b98b28abea28c9f3fc307722d17c2ad15826983657c"

  strings:
    $s1  = "h.pow(Math.cos(669), 2) - 1)); while(true) { if(FKIkSLnZG[INDWToVltth] > oBBxi[INDWToVltth].length-(-388+976)/588) { break; } if" ascii
    $s2  = ") - 1));while(true){if (INDWToVltth >= (-535+673)/23){break;}FKIkSLnZG[INDWToVltth]=Math.round((Math.pow(Math.sin(669), 2) + Mat" ascii
    $s3  = "ow(Math.cos(427), 2) - 1)));} FKIkSLnZG[INDWToVltth]++;}INDWToVltth++;} return PHfiwXdRAsW}" fullword ascii
    $s4  = "function tNZqWMwMHkkMulvgA(oBBxi){PHfiwXdRAsW= '';INDWToVltth=Math.round((Math.pow(Math.sin(143), 2) + Math.pow(Math.cos(143), 2" ascii
    $s5  = "function tNZqWMwMHkkMulvgA(oBBxi){PHfiwXdRAsW= '';INDWToVltth=Math.round((Math.pow(Math.sin(143), 2) + Math.pow(Math.cos(143), 2" ascii
    $s6  = "function KbZHLnd(OBTdynWeRjXfsfbNCNmiupkJKIdXfzFoglsd) {return !qukgUZRfchH(ylNRpuAnVASUUvK(OBTdynWeRjXfsfbNCNmiupkJKIdXfzFoglsd" ascii
    $s7  = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s8  = "function qukgUZRfchH(kXjrmkfLKrRAQt) {return isNaN(kXjrmkfLKrRAQt);}" fullword ascii
    $s9  = "function W(VErVdrSZwnxGyv,nvAfKWniqRWKY,AJxqDrPYARi) {VErVdrSZwnxGyv[nvAfKWniqRWKY]=AJxqDrPYARi;}" fullword ascii
    $s10 = "function GfZlIyRYhEGAOGR(WatIELLMDrpdRTTuf,HXnavqfZJGAHmYstxCfLwwNzUmxgCyPisr,KGsROIdHtZFanzsFPhXShqPgWuyPRuaWQpL){eval(WatIELLM" ascii
    $s11 = "function NgNPMfkrBxWdauTPd(qrKnKjBxdG,eudJaQLPMl) {return parseInt(qrKnKjBxdG,eudJaQLPMl);}" fullword ascii
    $s12 = "function CKxUxfgEDXBLtZBRvVSQqQFRzjQbhzbTXjxaJpGWlBGtCimjGmylCT(DLwEopLEJveYn,mgDukdNIBXSxMb){ return tHlkUux[VQksmiWg[qtIdo(DLw" ascii
    $s13 = "function fJBoWGtnxqJF(PRkrTEZkkmYYV) {return isFinite(PRkrTEZkkmYYV);}" fullword ascii
    $s14 = "function p(MHupRlFidPSj,NxpMCzINpBLUFe){MHupRlFidPSj.push(NxpMCzINpBLUFe);}" fullword ascii
    $s15 = "function qtIdo(apKlwqwZGDf,HdPdZbAMepRKs,tZsVHpBn){cBhs=NgNPMfkrBxWdauTPd(apKlwqwZGDf,HdPdZbAMepRKs);zOIWh=cBhs.toString(tZsVHpB" ascii
    $s16 = "function CKxUxfgEDXBLtZBRvVSQqQFRzjQbhzbTXjxaJpGWlBGtCimjGmylCT(DLwEopLEJveYn,mgDukdNIBXSxMb){ return tHlkUux[VQksmiWg[qtIdo(DLw" ascii
    $s17 = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s18 = "function KbZHLnd(OBTdynWeRjXfsfbNCNmiupkJKIdXfzFoglsd) {return !qukgUZRfchH(ylNRpuAnVASUUvK(OBTdynWeRjXfsfbNCNmiupkJKIdXfzFoglsd" ascii
    $s19 = "function ylNRpuAnVASUUvK(MNjOSpTiNzExZJsuoiJ) {return parseFloat(MNjOSpTiNzExZJsuoiJ);}" fullword ascii
    $s20 = "function GfZlIyRYhEGAOGR(WatIELLMDrpdRTTuf,HXnavqfZJGAHmYstxCfLwwNzUmxgCyPisr,KGsROIdHtZFanzsFPhXShqPgWuyPRuaWQpL){eval(WatIELLM" ascii

  condition:
    uint16(0) == 0x5156 and
    8 of them
}