rule sig_20151211_8ce2d6f19d21c32a0cd2276eb97622b0 {
  meta:
    description = "datamaliciousorder - file 20151211_8ce2d6f19d21c32a0cd2276eb97622b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "826347811f56f4d9a4df9b2186b396f6478d31966e2734320f8d562f3bc6f2ca"

  strings:
    $s1  = "function VEfiDTG(eNmcdeiWhRQfiqqhXHmjhTPqSqhUCGDqcKIY) {return !isNaN(parseFloat(eNmcdeiWhRQfiqqhXHmjhTPqSqhUCGDqcKIY)) && isFin" ascii
    $s2  = "function VEfiDTG(eNmcdeiWhRQfiqqhXHmjhTPqSqhUCGDqcKIY) {return !isNaN(parseFloat(eNmcdeiWhRQfiqqhXHmjhTPqSqhUCGDqcKIY)) && isFin" ascii
    $s3  = "function tsmSHrlSUZDVzPmnl(oRZFf){yWUSdAQRlIn= '';HRhfqrCeQLn=(-212+212)/296; while(true){if(HRhfqrCeQLn >= (-761+841)/40)break;" ascii
    $s4  = "function ePeQXCJaLZuTOVOVrERckwYZhdrbvMedXIJcJkanwNdnxuETEOIGyU(sGRZMZicQTOkV,YNZUVHDLIYOUhb){ return xGOBA[ycetv(sGRZMZicQTOkV[" ascii
    $s5  = "function tsmSHrlSUZDVzPmnl(oRZFf){yWUSdAQRlIn= '';HRhfqrCeQLn=(-212+212)/296; while(true){if(HRhfqrCeQLn >= (-761+841)/40)break;" ascii
    $s6  = "var x=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = " ZrAOx;}function ShAZJBVRohvQXuh(xlNywYipqeAkLxxFl){eval(xlNywYipqeAkLxxFl)}" fullword ascii
    $s8  = "function RtprOaNmWFL(jBnxAzQS,mCzOVM){return jBnxAzQS.split(mCzOVM)}" fullword ascii
    $s9  = "function ycetv(hKecgAQXuyP,iZcoKmGrOwMhD,dVMTMxhF){YklP=parseInt(hKecgAQXuyP,iZcoKmGrOwMhD);ZrAOx=YklP.toString(dVMTMxhF);return" ascii
    $s10 = "]++;}HRhfqrCeQLn++;} return yWUSdAQRlIn}" fullword ascii
    $s11 = "yQfeAHrMj[HRhfqrCeQLn]=(-770+770)/373; while(true) { if(yQfeAHrMj[HRhfqrCeQLn] > oRZFf[HRhfqrCeQLn].length-(-299+688)/389) { bre" ascii
    $s12 = "var e=new Array(\"26\",\"26\",\"2f\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function ycetv(hKecgAQXuyP,iZcoKmGrOwMhD,dVMTMxhF){YklP=parseInt(hKecgAQXuyP,iZcoKmGrOwMhD);ZrAOx=YklP.toString(dVMTMxhF);return" ascii
    $s14 = "function ePeQXCJaLZuTOVOVrERckwYZhdrbvMedXIJcJkanwNdnxuETEOIGyU(sGRZMZicQTOkV,YNZUVHDLIYOUhb){ return xGOBA[ycetv(sGRZMZicQTOkV[" ascii
    $s15 = "var x=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "var e=new Array(\"26\",\"26\",\"2f\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}