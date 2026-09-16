rule sig_20151210_30f77bc4205016134143cde1a21c797d {
  meta:
    description = "datamaliciousorder - file 20151210_30f77bc4205016134143cde1a21c797d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22c4a2dcd9822091e99e7c3801bdf838e3f4ce08665a6fdf8fb6b53c05256592"

  strings:
    $s1  = "function YicGKDR(AavmNFeDeZBLNDuSNFPpbCfHkjBRRsShNhkG) {return !isNaN(parseFloat(AavmNFeDeZBLNDuSNFPpbCfHkjBRRsShNhkG)) && isFin" ascii
    $s2  = "function YicGKDR(AavmNFeDeZBLNDuSNFPpbCfHkjBRRsShNhkG) {return !isNaN(parseFloat(AavmNFeDeZBLNDuSNFPpbCfHkjBRRsShNhkG)) && isFin" ascii
    $s3  = "function SKPOoiNdLwQ(pszvoDKK,zMEtip){return pszvoDKK.split(zMEtip)}" fullword ascii
    $s4  = "function JXVPu(RQiQKNmeiBk,nKveZNOrlqHSk,TNpYiicQ){XAdr=parseInt(RQiQKNmeiBk,nKveZNOrlqHSk);cCptw=XAdr.toString(TNpYiicQ);return" ascii
    $s5  = " cCptw;}function FOhNlfpAsExJDju(FUIyNXxlPUiSpjxNB){eval(FUIyNXxlPUiSpjxNB)}" fullword ascii
    $s6  = "function YqwLyvQIFhKvoygnB(BISlU){QEuwJwuOXFn= '';for(nncjKBCtNGN=(-699+699)/993; nncjKBCtNGN < (1073+415)/744; nncjKBCtNGN++) {" ascii
    $s7  = "SMLtQaI=(-438+438)/664;while(true){if(SMLtQaI>=(72250+70)/565){break;}QIhYFgdPdvIhs[SMLtQaI]=String.fromCharCode(SMLtQaI);SMLtQa" ascii
    $s8  = "function YqwLyvQIFhKvoygnB(BISlU){QEuwJwuOXFn= '';for(nncjKBCtNGN=(-699+699)/993; nncjKBCtNGN < (1073+415)/744; nncjKBCtNGN++) {" ascii
    $s9  = "function JXVPu(RQiQKNmeiBk,nKveZNOrlqHSk,TNpYiicQ){XAdr=parseInt(RQiQKNmeiBk,nKveZNOrlqHSk);cCptw=XAdr.toString(TNpYiicQ);return" ascii
    $s10 = "N]++;}} return QEuwJwuOXFn}" fullword ascii
    $s11 = "APMWBsdnz[nncjKBCtNGN]=(-221+221)/234; while(true) { if(APMWBsdnz[nncjKBCtNGN] > BISlU[nncjKBCtNGN].length-(-369+485)/116) { bre" ascii
    $s12 = "SMLtQaI=(-438+438)/664;while(true){if(SMLtQaI>=(72250+70)/565){break;}QIhYFgdPdvIhs[SMLtQaI]=String.fromCharCode(SMLtQaI);SMLtQa" ascii
    $s13 = "function maBqOYEkDGhqguSibtyEolfPimaWAaUZkIJySvVWdVNfBOPEiPcJFF(rmCegWzXgkWMt,KslnzUQChguMca){ return QIhYFgdPdvIhs[JXVPu(rmCegW" ascii
    $s14 = "function maBqOYEkDGhqguSibtyEolfPimaWAaUZkIJySvVWdVNfBOPEiPcJFF(rmCegWzXgkWMt,KslnzUQChguMca){ return QIhYFgdPdvIhs[JXVPu(rmCegW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}