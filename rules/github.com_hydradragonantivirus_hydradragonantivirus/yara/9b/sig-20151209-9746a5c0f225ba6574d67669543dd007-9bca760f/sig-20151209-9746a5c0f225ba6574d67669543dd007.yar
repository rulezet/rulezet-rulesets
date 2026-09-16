rule sig_20151209_9746a5c0f225ba6574d67669543dd007 {
  meta:
    description = "datamaliciousorder - file 20151209_9746a5c0f225ba6574d67669543dd007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa5c0250ef5682343176792e44d689088fb3f0ec1de6d88ae2b7d201232b8f9f"

  strings:
    $s1  = "QSlbgVvQW[SdSKSjziOMs]=(-367+367)/721; while(true) { if(QSlbgVvQW[SdSKSjziOMs] > GNgle[SdSKSjziOMs].length-(-151+429)/278) { bre" ascii
    $s2  = "++;}} return qdyplYbZCGV}" fullword ascii
    $s3  = "function oIpcE(EQIgcFPHqpo,wfivgfcZTXcSx,BexubxiE){wRqX=parseInt(EQIgcFPHqpo,wfivgfcZTXcSx);qvfMv=wRqX.toString(BexubxiE);return" ascii
    $s4  = " qvfMv;}function AJzqGNqOTQtjjGV(YLuooisttxBclFKnG){eval(YLuooisttxBclFKnG)}" fullword ascii
    $s5  = "function qUbhHumWFGfOlEvAR(GNgle){qdyplYbZCGV= '';for(SdSKSjziOMs=(-874+874)/787; SdSKSjziOMs < (1558+278)/918; SdSKSjziOMs++) {" ascii
    $s6  = "function QnSqDwNvrIdpwFiJNTyQumDvmcwpgmHpyqUVVWATUrNhAFPQSxieEV(PJmpxtJWcdXOB,AZsIalUVSYhBrO){ return lkRrt[oIpcE(PJmpxtJWcdXOB[" ascii
    $s7  = "function QnSqDwNvrIdpwFiJNTyQumDvmcwpgmHpyqUVVWATUrNhAFPQSxieEV(PJmpxtJWcdXOB,AZsIalUVSYhBrO){ return lkRrt[oIpcE(PJmpxtJWcdXOB[" ascii
    $s8  = "function oIpcE(EQIgcFPHqpo,wfivgfcZTXcSx,BexubxiE){wRqX=parseInt(EQIgcFPHqpo,wfivgfcZTXcSx);qvfMv=wRqX.toString(BexubxiE);return" ascii
    $s9  = "function mOKqpYYpyGb(qgFAvDFW,FKwNFH){return qgFAvDFW.split(FKwNFH)}" fullword ascii
    $s10 = "function vcavuME(tvVimZHSAwHGDFvIXjiXeNtMxzOkZmGgRLSi) {return !isNaN(parseFloat(tvVimZHSAwHGDFvIXjiXeNtMxzOkZmGgRLSi)) && isFin" ascii
    $s11 = "function vcavuME(tvVimZHSAwHGDFvIXjiXeNtMxzOkZmGgRLSi) {return !isNaN(parseFloat(tvVimZHSAwHGDFvIXjiXeNtMxzOkZmGgRLSi)) && isFin" ascii
    $s12 = "function qUbhHumWFGfOlEvAR(GNgle){qdyplYbZCGV= '';for(SdSKSjziOMs=(-874+874)/787; SdSKSjziOMs < (1558+278)/918; SdSKSjziOMs++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}