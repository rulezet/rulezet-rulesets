rule sig_20151217_887309f4adfe1a7e6cead6e7a35b7fdf {
  meta:
    description = "datamaliciousorder - file 20151217_887309f4adfe1a7e6cead6e7a35b7fdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e1340d9c3539a82bdf12f03cedbb168d5d5f55f576fdee649a52ee55a4c5e06"

  strings:
    $s1  = "function dLpjFJFmlxtSZxQlk(XdNCq){bYCZJnkwoqJ= '';CUPnhHdwzbf=Math.round((Math.pow(Math.sin(291), 2) + Math.pow(Math.cos(291), 2" ascii
    $s2  = "th.pow(Math.cos(647), 2) - 1)); while(true) { if(ghSFZuhJe[CUPnhHdwzbf] > XdNCq[CUPnhHdwzbf].length-(96+903)/999) { break; } if " ascii
    $s3  = ") - 1));while(true){if (CUPnhHdwzbf >= (3959+955)/819){break;}ghSFZuhJe[CUPnhHdwzbf]=Math.round((Math.pow(Math.sin(647), 2) + Ma" ascii
    $s4  = "ow(Math.cos(633), 2) - 1)));} ghSFZuhJe[CUPnhHdwzbf]++;}CUPnhHdwzbf++;} return bYCZJnkwoqJ}" fullword ascii
    $s5  = "function dLpjFJFmlxtSZxQlk(XdNCq){bYCZJnkwoqJ= '';CUPnhHdwzbf=Math.round((Math.pow(Math.sin(291), 2) + Math.pow(Math.cos(291), 2" ascii
    $s6  = "function tOMceHG(GSLTMMOOaGdZQJfOIIiAvXHuNityrTqtiqMN) {return !ppcttVqmyar(oolpYnwoaOOCvUz(GSLTMMOOaGdZQJfOIIiAvXHuNityrTqtiqMN" ascii
    $s7  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s8  = "function ssVZQLNtFHzPFkj(KXKvZBrTDqSWfhVUG,rCzrjJmTJgKmPLngyTkoSVwANzbAgHubUo,pCRIEfAXNivlWURLmPDwZMgYHGgYnApjxhi){eval(KXKvZBrT" ascii
    $s9  = "function ExVvgshfsfERJXOdNRMGJZFJdtZbXMwJttWFtCXUZkjhXkTTYmJKrM(htGteBdZFvRIy,qsEyFMFluWBtsX){ return hFyvGuD[VEQuuUah[bVVCU(htG" ascii
    $s10 = "function bVVCU(xCRUoArsXtx,zEaMpXgjYlsjl,DhdyoquR){klps=TBhwyqipbsVTTtLLZ(xCRUoArsXtx,zEaMpXgjYlsjl);pEKAR=klps.toString(Dhdyoqu" ascii
    $s11 = "function TBhwyqipbsVTTtLLZ(AeHJTSmeSF,ZWfnoocbTg) {return parseInt(AeHJTSmeSF,ZWfnoocbTg);}" fullword ascii
    $s12 = "function ppcttVqmyar(kIJPEuyTAbCoqV) {return isNaN(kIJPEuyTAbCoqV);}" fullword ascii
    $s13 = "function bVVCU(xCRUoArsXtx,zEaMpXgjYlsjl,DhdyoquR){klps=TBhwyqipbsVTTtLLZ(xCRUoArsXtx,zEaMpXgjYlsjl);pEKAR=klps.toString(Dhdyoqu" ascii
    $s14 = "function U(qbZSnoDpbIaSvW,JgjeEqFzZoazN,XxkxOAZKXcW) {qbZSnoDpbIaSvW[JgjeEqFzZoazN]=XxkxOAZKXcW;}" fullword ascii
    $s15 = "R);return pEKAR;}" fullword ascii
    $s16 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s17 = "function ExVvgshfsfERJXOdNRMGJZFJdtZbXMwJttWFtCXUZkjhXkTTYmJKrM(htGteBdZFvRIy,qsEyFMFluWBtsX){ return hFyvGuD[VEQuuUah[bVVCU(htG" ascii
    $s18 = "function XrpbxlvTtqMV(UBoEDDpaQpxZc) {return isFinite(UBoEDDpaQpxZc);}" fullword ascii
    $s19 = "function oolpYnwoaOOCvUz(WTTegpGaUBliXtAsUgJ) {return parseFloat(WTTegpGaUBliXtAsUgJ);}" fullword ascii
    $s20 = "function tOMceHG(GSLTMMOOaGdZQJfOIIiAvXHuNityrTqtiqMN) {return !ppcttVqmyar(oolpYnwoaOOCvUz(GSLTMMOOaGdZQJfOIIiAvXHuNityrTqtiqMN" ascii

  condition:
    uint16(0) == 0x4556 and
    8 of them
}