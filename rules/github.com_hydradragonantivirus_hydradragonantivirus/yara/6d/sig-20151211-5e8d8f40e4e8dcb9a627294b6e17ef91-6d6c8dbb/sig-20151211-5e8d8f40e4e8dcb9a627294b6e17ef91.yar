rule sig_20151211_5e8d8f40e4e8dcb9a627294b6e17ef91 {
  meta:
    description = "datamaliciousorder - file 20151211_5e8d8f40e4e8dcb9a627294b6e17ef91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5a263dc416bfa0c570eaf7089d9724c13c4e5bf6d0a8d1d2e16f438db9e4aac"

  strings:
    $s1  = "function VwKGTsc(egGXrmvqmnIaAUCPvDGtQlBgGleSSOnOQMIU) {return !isNaN(parseFloat(egGXrmvqmnIaAUCPvDGtQlBgGleSSOnOQMIU)) && isFin" ascii
    $s2  = "function VwKGTsc(egGXrmvqmnIaAUCPvDGtQlBgGleSSOnOQMIU) {return !isNaN(parseFloat(egGXrmvqmnIaAUCPvDGtQlBgGleSSOnOQMIU)) && isFin" ascii
    $s3  = "var U=new Array(\"27\",\"26\",\"26\",\"2f\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s4  = " Llgjj;}function GTzitZnIsBuAjRH(XQYXXlUCiFUUFeVRc){eval(XQYXXlUCiFUUFeVRc)}" fullword ascii
    $s5  = "var s=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function PAZqR(UCekMsHLwgw,XfHmkzkskjwKA,gZkygehq){AldH=parseInt(UCekMsHLwgw,XfHmkzkskjwKA);Llgjj=AldH.toString(gZkygehq);return" ascii
    $s7  = "function thmknBnJlgjwfKigL(QLERr){LlYLSUrNAFR= '';TASeAxcEnbF=(-245+245)/919; while(true){if(TASeAxcEnbF >= (1731+153)/942)break" ascii
    $s8  = "var s=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "function PAZqR(UCekMsHLwgw,XfHmkzkskjwKA,gZkygehq){AldH=parseInt(UCekMsHLwgw,XfHmkzkskjwKA);Llgjj=AldH.toString(gZkygehq);return" ascii
    $s10 = "var U=new Array(\"27\",\"26\",\"26\",\"2f\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "function fsoCJXmLISa(eXqZMcWb,aVnqFH){return eXqZMcWb.split(aVnqFH)}" fullword ascii
    $s12 = ";FpSsxdKez[TASeAxcEnbF]=(-834+834)/576; while(true) { if(FpSsxdKez[TASeAxcEnbF] > QLERr[TASeAxcEnbF].length-(-651+733)/82) { bre" ascii
    $s13 = "]++;}TASeAxcEnbF++;} return LlYLSUrNAFR}" fullword ascii
    $s14 = "function FPWdpYfhDixvtpIOveIivQYuGDhFOgaZwcxkscayAAmXOVkXtpYjxi(etTHxMfaWduCq,QwfGRAhzdmLdio){ return iCGiq[PAZqR(etTHxMfaWduCq[" ascii
    $s15 = "function FPWdpYfhDixvtpIOveIivQYuGDhFOgaZwcxkscayAAmXOVkXtpYjxi(etTHxMfaWduCq,QwfGRAhzdmLdio){ return iCGiq[PAZqR(etTHxMfaWduCq[" ascii
    $s16 = "function thmknBnJlgjwfKigL(QLERr){LlYLSUrNAFR= '';TASeAxcEnbF=(-245+245)/919; while(true){if(TASeAxcEnbF >= (1731+153)/942)break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}