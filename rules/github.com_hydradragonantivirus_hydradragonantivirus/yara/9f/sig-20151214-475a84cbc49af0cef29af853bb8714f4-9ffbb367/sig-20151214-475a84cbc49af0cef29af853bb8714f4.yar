rule sig_20151214_475a84cbc49af0cef29af853bb8714f4 {
  meta:
    description = "datamaliciousorder - file 20151214_475a84cbc49af0cef29af853bb8714f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfd4857f3257cf8a767f7c31f04860ea8a4406bcf59d5c9fe0c4f7775f50ba89"

  strings:
    $s1  = "th.cos(773), 2) - 1)));} VbpvwLddQ[esdvWZVEwvD]++;}} return pJWXSEdWgWk}" fullword ascii
    $s2  = "pow(Math.cos(749), 2) - 1)); while(true) { if(VbpvwLddQ[esdvWZVEwvD] > TnNYs[esdvWZVEwvD].length-(95+261)/356) { break; } if (Hs" ascii
    $s3  = "5), 2) - 1)); esdvWZVEwvD < (220+552)/386; esdvWZVEwvD++) {VbpvwLddQ[esdvWZVEwvD]=Math.round((Math.pow(Math.sin(749), 2) + Math." ascii
    $s4  = "function BwwKbhKSaknZKwmXm(TnNYs){pJWXSEdWgWk= V[1804];for(esdvWZVEwvD=Math.round((Math.pow(Math.sin(5), 2) + Math.pow(Math.cos(" ascii
    $s5  = "function BwwKbhKSaknZKwmXm(TnNYs){pJWXSEdWgWk= V[1804];for(esdvWZVEwvD=Math.round((Math.pow(Math.sin(5), 2) + Math.pow(Math.cos(" ascii
    $s6  = "function YYccbycGhrX(wJENTget,SitdIz){return wJENTget.split(SitdIz)}" fullword ascii
    $s7  = "NBBC)) {return (String.fromCharCode(cKpOfBLxhRHXNBBC) + String.fromCharCode((15249+723)/363));}}" fullword ascii
    $s8  = "function g(ijRedRIUFqFX,orzrQlcFnXiZAI){ijRedRIUFqFX.push(orzrQlcFnXiZAI);}function t2(cKpOfBLxhRHXNBBC){if(HsTKNuM(cKpOfBLxhRHX" ascii
    $s9  = "function HsTKNuM(aOZNCYJSwJDOUzgnmVexnoYTiemBFAUwDzVs) {return !isNaN(parseFloat(aOZNCYJSwJDOUzgnmVexnoYTiemBFAUwDzVs)) && isFin" ascii
    $s10 = "function HsTKNuM(aOZNCYJSwJDOUzgnmVexnoYTiemBFAUwDzVs) {return !isNaN(parseFloat(aOZNCYJSwJDOUzgnmVexnoYTiemBFAUwDzVs)) && isFin" ascii
    $s11 = "var V=new Array();" fullword ascii
    $s12 = "function uiDpS(CBrQBOLNaTt,QCUOagKgtWvPz,sLVwdYaX){OrWg=parseInt(CBrQBOLNaTt,QCUOagKgtWvPz);TWzup=OrWg.toString(sLVwdYaX);return" ascii
    $s13 = "function DBbydqzmRUkywDF(AUQZuwJXkmoYlnMrG){eval(AUQZuwJXkmoYlnMrG)}" fullword ascii
    $s14 = "function uiDpS(CBrQBOLNaTt,QCUOagKgtWvPz,sLVwdYaX){OrWg=parseInt(CBrQBOLNaTt,QCUOagKgtWvPz);TWzup=OrWg.toString(sLVwdYaX);return" ascii
    $s15 = "function mBOsdGTBerTJloUBKXtWlxwCwIpXtrmYVJsXMFgEueGvNdzlwSVtGC(zUViRurcQUBFT,fUmmYtbqIpFuEm){ return ejKjPyQ[xuhbdatH[uiDpS(zUV" ascii
    $s16 = "function mBOsdGTBerTJloUBKXtWlxwCwIpXtrmYVJsXMFgEueGvNdzlwSVtGC(zUViRurcQUBFT,fUmmYtbqIpFuEm){ return ejKjPyQ[xuhbdatH[uiDpS(zUV" ascii
    $s17 = "function g(ijRedRIUFqFX,orzrQlcFnXiZAI){ijRedRIUFqFX.push(orzrQlcFnXiZAI);}function t2(cKpOfBLxhRHXNBBC){if(HsTKNuM(cKpOfBLxhRHX" ascii
    $s18 = " TWzup;}function DBbydqzmRUkywDF(AUQZuwJXkmoYlnMrG,nnOAeUsINoCwnranrDaJMqvydaAjKAgttA,HiwbmBCSUDrGwaZELlWpvgiqRxzyqsawpAq){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}