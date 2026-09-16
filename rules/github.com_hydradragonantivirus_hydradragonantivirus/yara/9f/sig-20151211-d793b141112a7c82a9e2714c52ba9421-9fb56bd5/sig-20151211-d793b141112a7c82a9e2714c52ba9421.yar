rule sig_20151211_d793b141112a7c82a9e2714c52ba9421 {
  meta:
    description = "datamaliciousorder - file 20151211_d793b141112a7c82a9e2714c52ba9421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcaea56e7d1e46ed7c78b2f8ff7cca0cf51f6c1840d1d2d2e593caecb2f4b048"

  strings:
    $s1  = "function xithm(LOGrvJwFuJl,uSYYFpqRCpQlJ,uDpuOvJN){LYSE=parseInt(LOGrvJwFuJl,uSYYFpqRCpQlJ);xPfFv=LYSE.toString(uDpuOvJN);return" ascii
    $s2  = "function xithm(LOGrvJwFuJl,uSYYFpqRCpQlJ,uDpuOvJN){LYSE=parseInt(LOGrvJwFuJl,uSYYFpqRCpQlJ);xPfFv=LYSE.toString(uDpuOvJN);return" ascii
    $s3  = "VhtydGNvM[FghTCLQmOzI]=(-330+330)/21; while(true) { if(VhtydGNvM[FghTCLQmOzI] > ciMoS[FghTCLQmOzI].length-(-403+873)/470) { brea" ascii
    $s4  = "]++;}FghTCLQmOzI++;} return DztHECcppmb}" fullword ascii
    $s5  = "function XHxZJvrDFGh(leJtMTCt,NZatYy){return leJtMTCt.split(NZatYy)}" fullword ascii
    $s6  = "function OGnCWQWcuhOKKPaNkcyUdjSpGtIujqEMyPiBUWUcEWZdViMGMBsFDJ(cCqOCLoxgAnDR,OUSTqxzrXuAxHs){ return zEmBb[xithm(cCqOCLoxgAnDR[" ascii
    $s7  = "var Q=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"52\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "var w=new Array(\"2d\",\"27\",\"27\",\"2e\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "function WQWSHcFQfZgnuVQzU(ciMoS){DztHECcppmb= '';FghTCLQmOzI=(-934+934)/328; while(true){if(FghTCLQmOzI >= (254+836)/545)break;" ascii
    $s10 = "var Q=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"52\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var w=new Array(\"2d\",\"27\",\"27\",\"2e\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = " xPfFv;}function xheaZhIoeCBwwfK(QNQnsPWQxbqlAcbRB){eval(QNQnsPWQxbqlAcbRB)}" fullword ascii
    $s13 = "function WQWSHcFQfZgnuVQzU(ciMoS){DztHECcppmb= '';FghTCLQmOzI=(-934+934)/328; while(true){if(FghTCLQmOzI >= (254+836)/545)break;" ascii
    $s14 = "function OGnCWQWcuhOKKPaNkcyUdjSpGtIujqEMyPiBUWUcEWZdViMGMBsFDJ(cCqOCLoxgAnDR,OUSTqxzrXuAxHs){ return zEmBb[xithm(cCqOCLoxgAnDR[" ascii
    $s15 = "function DhZlPoA(nllJdeDCAydhNubuGrkGmNggZtLsDTuPppSN) {return !isNaN(parseFloat(nllJdeDCAydhNubuGrkGmNggZtLsDTuPppSN)) && isFin" ascii
    $s16 = "function DhZlPoA(nllJdeDCAydhNubuGrkGmNggZtLsDTuPppSN) {return !isNaN(parseFloat(nllJdeDCAydhNubuGrkGmNggZtLsDTuPppSN)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}