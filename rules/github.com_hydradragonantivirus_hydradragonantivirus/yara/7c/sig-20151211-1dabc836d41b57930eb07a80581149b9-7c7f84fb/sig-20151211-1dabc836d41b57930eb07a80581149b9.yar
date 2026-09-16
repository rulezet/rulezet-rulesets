rule sig_20151211_1dabc836d41b57930eb07a80581149b9 {
  meta:
    description = "datamaliciousorder - file 20151211_1dabc836d41b57930eb07a80581149b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b1bbf187d3bbfac05899d1cdd95bb47508f490fedeb48e641218425faed286"

  strings:
    $s1  = "function mJBAFyb(FGkxaaLSclWEvKNNBKBStoOEikDTbgXcJfxc) {return !isNaN(parseFloat(FGkxaaLSclWEvKNNBKBStoOEikDTbgXcJfxc)) && isFin" ascii
    $s2  = "function mJBAFyb(FGkxaaLSclWEvKNNBKBStoOEikDTbgXcJfxc) {return !isNaN(parseFloat(FGkxaaLSclWEvKNNBKBStoOEikDTbgXcJfxc)) && isFin" ascii
    $s3  = "VPYihQvEg[majlcyLfXYq]=(-586+586)/769; while(true) { if(VPYihQvEg[majlcyLfXYq] > ETJKy[majlcyLfXYq].length-(647+161)/808) { brea" ascii
    $s4  = "var c=new Array(\"2f\",\"2d\",\"28\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s5  = "function kFtvzqNTjUEDFOHbZOxaQrJBVOWRTHbGbUDImKNnqjpRfemObRPtIi(gbnUeWPFKCtTg,STBIOCSTxdYNAM){ return hTsaT[kMeXD(gbnUeWPFKCtTg[" ascii
    $s6  = "++;}majlcyLfXYq++;} return lxAbtYiVxZf}" fullword ascii
    $s7  = "function PczLFHhNiua(oLXqoZsW,jgEcYk){return oLXqoZsW.split(jgEcYk)}" fullword ascii
    $s8  = "function UZpONJqvWWtJKlAft(ETJKy){lxAbtYiVxZf= '';majlcyLfXYq=(-132+132)/979; while(true){if(majlcyLfXYq >= (598+986)/792)break;" ascii
    $s9  = "function UZpONJqvWWtJKlAft(ETJKy){lxAbtYiVxZf= '';majlcyLfXYq=(-132+132)/979; while(true){if(majlcyLfXYq >= (598+986)/792)break;" ascii
    $s10 = "function kMeXD(uHzlevUkpYT,jRnVSCCBYjlSj,DHLVfBUM){QsmI=parseInt(uHzlevUkpYT,jRnVSCCBYjlSj);fsBQj=QsmI.toString(DHLVfBUM);return" ascii
    $s11 = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "function kFtvzqNTjUEDFOHbZOxaQrJBVOWRTHbGbUDImKNnqjpRfemObRPtIi(gbnUeWPFKCtTg,STBIOCSTxdYNAM){ return hTsaT[kMeXD(gbnUeWPFKCtTg[" ascii
    $s14 = "var c=new Array(\"2f\",\"2d\",\"28\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s15 = "function kMeXD(uHzlevUkpYT,jRnVSCCBYjlSj,DHLVfBUM){QsmI=parseInt(uHzlevUkpYT,jRnVSCCBYjlSj);fsBQj=QsmI.toString(DHLVfBUM);return" ascii
    $s16 = " fsBQj;}function ccaDBNYCGWKHltR(GbQkdlrOfIqIXzIuC){eval(GbQkdlrOfIqIXzIuC)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}