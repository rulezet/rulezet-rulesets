rule sig_20151209_94664f578acc5a26a18b9ce8498dd7f6 {
  meta:
    description = "datamaliciousorder - file 20151209_94664f578acc5a26a18b9ce8498dd7f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c2c06b4b5fcbc7fb80e47c11a07ccdb55c7e66d117916e0c7bacff4497bbef6"

  strings:
    $s1  = "function XsBRTPn(MfPlDbbrsKXrBwpuPPQnAjegfGdkfqeEuHZV) {return !isNaN(parseFloat(MfPlDbbrsKXrBwpuPPQnAjegfGdkfqeEuHZV)) && isFin" ascii
    $s2  = "function XsBRTPn(MfPlDbbrsKXrBwpuPPQnAjegfGdkfqeEuHZV) {return !isNaN(parseFloat(MfPlDbbrsKXrBwpuPPQnAjegfGdkfqeEuHZV)) && isFin" ascii
    $s3  = ";}} return PRDAWPVVUVS}" fullword ascii
    $s4  = "function rhAkT(fwQTDecSAPR,HCXbSktSmNkTm,yuUnQlND){KXyi=parseInt(fwQTDecSAPR,HCXbSktSmNkTm);ZwhYc=KXyi.toString(yuUnQlND);return" ascii
    $s5  = "function VmiJZWTFGGePPPPwh(ufTHr){PRDAWPVVUVS= '';for(eEzaSuqKacU=(-380+380)/662; eEzaSuqKacU < (197+747)/472; eEzaSuqKacU++) {K" ascii
    $s6  = "function ZMKriBqfunH(WISFdQrA,LnMCYE){return WISFdQrA.split(LnMCYE)}" fullword ascii
    $s7  = "function CRafaVQifeWrNVgxKdMkaVzDkHitbyQObqefbmeeWhOmyMjIddeGOM(IobuOmFZKLfFw,mCDbpbbJjvwgNd){ return KVwNg[rhAkT(IobuOmFZKLfFw[" ascii
    $s8  = "function VmiJZWTFGGePPPPwh(ufTHr){PRDAWPVVUVS= '';for(eEzaSuqKacU=(-380+380)/662; eEzaSuqKacU < (197+747)/472; eEzaSuqKacU++) {K" ascii
    $s9  = "function CRafaVQifeWrNVgxKdMkaVzDkHitbyQObqefbmeeWhOmyMjIddeGOM(IobuOmFZKLfFw,mCDbpbbJjvwgNd){ return KVwNg[rhAkT(IobuOmFZKLfFw[" ascii
    $s10 = "EpsWWNXQ[eEzaSuqKacU]=(-364+364)/130; while(true) { if(KEpsWWNXQ[eEzaSuqKacU] > ufTHr[eEzaSuqKacU].length-(42+661)/703) { break;" ascii
    $s11 = "function rhAkT(fwQTDecSAPR,HCXbSktSmNkTm,yuUnQlND){KXyi=parseInt(fwQTDecSAPR,HCXbSktSmNkTm);ZwhYc=KXyi.toString(yuUnQlND);return" ascii
    $s12 = " ZwhYc;}function EcaGFzDHcqrANJR(okMrwvHTtlFgMWQyA){eval(okMrwvHTtlFgMWQyA)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}