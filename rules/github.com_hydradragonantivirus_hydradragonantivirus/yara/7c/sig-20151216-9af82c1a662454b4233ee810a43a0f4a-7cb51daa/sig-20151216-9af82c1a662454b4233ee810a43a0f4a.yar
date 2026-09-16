rule sig_20151216_9af82c1a662454b4233ee810a43a0f4a {
  meta:
    description = "datamaliciousorder - file 20151216_9af82c1a662454b4233ee810a43a0f4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a12dd5b0cd3a987a3cd6631f9291fd9f2e03fd01f3ca93e040f2dfbf334fa4be"

  strings:
    $s1  = "ow(Math.cos(377), 2) - 1)));} mlVCVffRL[ikGRVMFRbjy]++;}ikGRVMFRbjy++;} return ZZUxiloKRPA}" fullword ascii
    $s2  = "function KnQhIgoAnoNUgWPWA(ljFLR){ZZUxiloKRPA= '';ikGRVMFRbjy=Math.round((Math.pow(Math.sin(905), 2) + Math.pow(Math.cos(905), 2" ascii
    $s3  = "h.pow(Math.cos(915), 2) - 1)); while(true) { if(mlVCVffRL[ikGRVMFRbjy] > ljFLR[ikGRVMFRbjy].length-(-53+599)/546) { break; } if " ascii
    $s4  = ") - 1));while(true){if (ikGRVMFRbjy >= (-203+335)/22){break;}mlVCVffRL[ikGRVMFRbjy]=Math.round((Math.pow(Math.sin(915), 2) + Mat" ascii
    $s5  = "function KnQhIgoAnoNUgWPWA(ljFLR){ZZUxiloKRPA= '';ikGRVMFRbjy=Math.round((Math.pow(Math.sin(905), 2) + Math.pow(Math.cos(905), 2" ascii
    $s6  = "function kAGvEqD(lWpiRevipkxyeIIpzdaqNHtjNIARtNruUcGK) {return !vmxbuGZrTVB(lPApozSIvdvvuWB(lWpiRevipkxyeIIpzdaqNHtjNIARtNruUcGK" ascii
    $s7  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s8  = "function Q(AQioYzlcfQFC,CDTUPkuMSZkkuW){AQioYzlcfQFC.push(CDTUPkuMSZkkuW);}" fullword ascii
    $s9  = "function VnMXB(HuQdQMSdyOD,agKLGBjvijDfO,mbvkudCc){JLbX=zUhhPOSklUMMfhwgX(HuQdQMSdyOD,agKLGBjvijDfO);NGsSY=JLbX.toString(mbvkudC" ascii
    $s10 = "c);return NGsSY;}" fullword ascii
    $s11 = "function VnMXB(HuQdQMSdyOD,agKLGBjvijDfO,mbvkudCc){JLbX=zUhhPOSklUMMfhwgX(HuQdQMSdyOD,agKLGBjvijDfO);NGsSY=JLbX.toString(mbvkudC" ascii
    $s12 = "function bZllMWguRrbvZBjPRebYbbxXNkRkqKTZrljpEniOzbORVlYhHEaXxB(WhhsDvmUZFtVm,nyJdwiLDyqwjXw){ return poiQgKX[xqmeihmH[VnMXB(Whh" ascii
    $s13 = "function vmxbuGZrTVB(uJOiGLEnkXURBu) {return isNaN(uJOiGLEnkXURBu);}" fullword ascii
    $s14 = "function kKcUaNawcLmjwMn(hFxDuFTIWBQNaKRuJ,DYxpqErNIilkOEMivaLtJdOUHDKcXIpRGG,KLGeahviEMxYzafAOxkRmFLSeznqdMDHnOy){eval(hFxDuFTI" ascii
    $s15 = "function kAGvEqD(lWpiRevipkxyeIIpzdaqNHtjNIARtNruUcGK) {return !vmxbuGZrTVB(lPApozSIvdvvuWB(lWpiRevipkxyeIIpzdaqNHtjNIARtNruUcGK" ascii
    $s16 = "function y(tLuEoCMGWMModO,GZTwIRNmDHCOc,TwfFyEFtgTp) {tLuEoCMGWMModO[GZTwIRNmDHCOc]=TwfFyEFtgTp;}" fullword ascii
    $s17 = "function kKcUaNawcLmjwMn(hFxDuFTIWBQNaKRuJ,DYxpqErNIilkOEMivaLtJdOUHDKcXIpRGG,KLGeahviEMxYzafAOxkRmFLSeznqdMDHnOy){eval(hFxDuFTI" ascii
    $s18 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s19 = "function jqXwBcQmvEnj(eAPZgRsCxJmMW) {return isFinite(eAPZgRsCxJmMW);}" fullword ascii
    $s20 = "function lPApozSIvdvvuWB(paEFZdhdhCbPLaCKEUC) {return parseFloat(paEFZdhdhCbPLaCKEUC);}" fullword ascii

  condition:
    uint16(0) == 0x7178 and
    8 of them
}