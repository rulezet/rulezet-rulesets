rule sig_20151214_4e0796da73c6e58b7b71861d06f15efb {
  meta:
    description = "datamaliciousorder - file 20151214_4e0796da73c6e58b7b71861d06f15efb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1b8f7ee7ad4d503437fa08a24bc51dd50ab34955c1348261a3d8c54c392e1c5"

  strings:
    $s1  = "ath.pow(Math.cos(499), 2) - 1)); while(true) { if(yWkDBAmNP[fnYozeAPLDC] > IIChO[fnYozeAPLDC].length-(-41+493)/452) { break; } i" ascii
    $s2  = ".pow(Math.cos(332), 2) - 1)));} yWkDBAmNP[fnYozeAPLDC]++;}} return cwavnzeEJlp}" fullword ascii
    $s3  = "function pPHsPLEMxyVSDazZb(IIChO){cwavnzeEJlp= p[1790];for(fnYozeAPLDC=Math.round((Math.pow(Math.sin(845), 2) + Math.pow(Math.co" ascii
    $s4  = "OdSpzzNYcPSuYgRkTfQRsRSEpsSAAOgLRVPa([IIChO[fnYozeAPLDC][yWkDBAmNP[fnYozeAPLDC]]], Math.round((Math.pow(Math.sin(332), 2) + Math" ascii
    $s5  = "function pPHsPLEMxyVSDazZb(IIChO){cwavnzeEJlp= p[1790];for(fnYozeAPLDC=Math.round((Math.pow(Math.sin(845), 2) + Math.pow(Math.co" ascii
    $s6  = "ZzTl)) {return (String.fromCharCode(QcDwWfJsYLfMZzTl) + String.fromCharCode((35054+865)/921));}}" fullword ascii
    $s7  = "function HJOfbiq(tRKLRWnCXfnrkGiiaXovzmhCjjfxrGjNtVKE) {return !isNaN(parseFloat(tRKLRWnCXfnrkGiiaXovzmhCjjfxrGjNtVKE)) && isFin" ascii
    $s8  = "function HJOfbiq(tRKLRWnCXfnrkGiiaXovzmhCjjfxrGjNtVKE) {return !isNaN(parseFloat(tRKLRWnCXfnrkGiiaXovzmhCjjfxrGjNtVKE)) && isFin" ascii
    $s9  = "function FkzWfRwXektzTjsablOdSpzzNYcPSuYgRkTfQRsRSEpsSAAOgLRVPa(lgsENqVVHlhAQ,aWDvaTAjyghzxm){ return srhluEx[CHngBVHM[pUEVX(lgs" ascii
    $s10 = "function vufPMGxxwnk(jeNPXVsr,hXJKrw){return jeNPXVsr.split(hXJKrw)}" fullword ascii
    $s11 = "function pUEVX(AKxrsSsJNit,RyBSHIqjfwLtz,qWyMyTRq){ghbj=parseInt(AKxrsSsJNit,RyBSHIqjfwLtz);IUjBv=ghbj.toString(qWyMyTRq);return" ascii
    $s12 = "function Z(jighghBIyXXm,SttcaLfGnFyeNC){jighghBIyXXm.push(SttcaLfGnFyeNC);}function y0(QcDwWfJsYLfMZzTl){if(HJOfbiq(QcDwWfJsYLfM" ascii
    $s13 = "function DlMBUakTnioPVZE(eQEtnTRvOzegtuMNy){eval(eQEtnTRvOzegtuMNy)}" fullword ascii
    $s14 = " IUjBv;}function DlMBUakTnioPVZE(eQEtnTRvOzegtuMNy,urKUUPImLehgWMgcVsCzKkrhUhoVWSEroX,FUPRvQYfBRmBHUCVGFBqjZxSKawczilbsPr){eval(" ascii
    $s15 = "function pUEVX(AKxrsSsJNit,RyBSHIqjfwLtz,qWyMyTRq){ghbj=parseInt(AKxrsSsJNit,RyBSHIqjfwLtz);IUjBv=ghbj.toString(qWyMyTRq);return" ascii
    $s16 = "var p=new Array();" fullword ascii
    $s17 = "function FkzWfRwXektzTjsablOdSpzzNYcPSuYgRkTfQRsRSEpsSAAOgLRVPa(lgsENqVVHlhAQ,aWDvaTAjyghzxm){ return srhluEx[CHngBVHM[pUEVX(lgs" ascii
    $s18 = "function Z(jighghBIyXXm,SttcaLfGnFyeNC){jighghBIyXXm.push(SttcaLfGnFyeNC);}function y0(QcDwWfJsYLfMZzTl){if(HJOfbiq(QcDwWfJsYLfM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}