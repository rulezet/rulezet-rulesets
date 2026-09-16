rule sig_20151214_ba1f416e08cf7a4c0774801c23f98231 {
  meta:
    description = "datamaliciousorder - file 20151214_ba1f416e08cf7a4c0774801c23f98231.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a67bb55d645915c7be2e1f78deb574eb8a04c06ee9da4223c1017badf017a67d"

  strings:
    $s1  = "ath.pow(Math.cos(548), 2) - 1)); while(true) { if(UXwZbKsyo[wFRHZrzZIWk] > ndfuM[wFRHZrzZIWk].length-(823+140)/963) { break; } i" ascii
    $s2  = "function PYYxDagWQNsboCSNb(ndfuM){YSrGrTRMOKN= T[1800];for(wFRHZrzZIWk=Math.round((Math.pow(Math.sin(770), 2) + Math.pow(Math.co" ascii
    $s3  = "(Math.cos(439), 2) - 1)));} UXwZbKsyo[wFRHZrzZIWk]++;}} return YSrGrTRMOKN}" fullword ascii
    $s4  = "function PYYxDagWQNsboCSNb(ndfuM){YSrGrTRMOKN= T[1800];for(wFRHZrzZIWk=Math.round((Math.pow(Math.sin(770), 2) + Math.pow(Math.co" ascii
    $s5  = "qCbX)) {return (String.fromCharCode(xOqSVhYIFyYuqCbX) + String.fromCharCode((29673+347)/790));}}" fullword ascii
    $s6  = "function O(FqsCwaXXEsKJ,pepxTTFjrmlzEJ){FqsCwaXXEsKJ.push(pepxTTFjrmlzEJ);}function Z4(xOqSVhYIFyYuqCbX){if(yqnLYLy(xOqSVhYIFyYu" ascii
    $s7  = "function yqnLYLy(SGnTMzuNsPjgZYkFskjYItSPrpXQURONfTNe) {return !isNaN(parseFloat(SGnTMzuNsPjgZYkFskjYItSPrpXQURONfTNe)) && isFin" ascii
    $s8  = "function yqnLYLy(SGnTMzuNsPjgZYkFskjYItSPrpXQURONfTNe) {return !isNaN(parseFloat(SGnTMzuNsPjgZYkFskjYItSPrpXQURONfTNe)) && isFin" ascii
    $s9  = "function O(FqsCwaXXEsKJ,pepxTTFjrmlzEJ){FqsCwaXXEsKJ.push(pepxTTFjrmlzEJ);}function Z4(xOqSVhYIFyYuqCbX){if(yqnLYLy(xOqSVhYIFyYu" ascii
    $s10 = "function YDfgPFgQZQwTKFtEvuBHVweMMZAkCyROKOcpvMVeZaiOigUAxrBHdV(edxifVUvSEXAz,CtzWPEGiTOyDhe){ return vKkIfdz[gCDuTGOp[BfOuP(edx" ascii
    $s11 = "function BfOuP(OYSRZdbSHEC,LJUDCqQiawESX,TlFWdVqp){NGon=parseInt(OYSRZdbSHEC,LJUDCqQiawESX);FUqxo=NGon.toString(TlFWdVqp);return" ascii
    $s12 = "function YDfgPFgQZQwTKFtEvuBHVweMMZAkCyROKOcpvMVeZaiOigUAxrBHdV(edxifVUvSEXAz,CtzWPEGiTOyDhe){ return vKkIfdz[gCDuTGOp[BfOuP(edx" ascii
    $s13 = "var T=new Array();" fullword ascii
    $s14 = "function BfOuP(OYSRZdbSHEC,LJUDCqQiawESX,TlFWdVqp){NGon=parseInt(OYSRZdbSHEC,LJUDCqQiawESX);FUqxo=NGon.toString(TlFWdVqp);return" ascii
    $s15 = "function BuzuYcaHNPLXnwY(lhXnHdQPGtfqRQpZr){eval(lhXnHdQPGtfqRQpZr)}" fullword ascii
    $s16 = " FUqxo;}function BuzuYcaHNPLXnwY(lhXnHdQPGtfqRQpZr,FdINKnJRoLBqvstaCheckUfaFQYqIzOymV,dFRlJnNDFaVmzvxCAxZuZFOivHKqRqmEZeC){eval(" ascii
    $s17 = "function JwbKLVyzqOG(lQdscycA,Ubyzbr){return lQdscycA.split(Ubyzbr)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}