rule sig_20151209_c11247058487b41c00997e8c007200d5 {
  meta:
    description = "datamaliciousorder - file 20151209_c11247058487b41c00997e8c007200d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d025099fddc023eeaba409cb034ae667e49bf4b53527e91ce7d24101ef2ccb30"

  strings:
    $s1  = "kWnUSfr[GpUqlLbaSRU]=(-377+377)/849; while(true) { if(ackWnUSfr[GpUqlLbaSRU] > xeKJD[GpUqlLbaSRU].length-(-318+745)/427) { break" ascii
    $s2  = "function iygCnKQIHHgBVMzgz(xeKJD){neFzLsGzFdJ= '';for(GpUqlLbaSRU=(-102+102)/15; GpUqlLbaSRU < (840+766)/803; GpUqlLbaSRU++) {ac" ascii
    $s3  = "function iygCnKQIHHgBVMzgz(xeKJD){neFzLsGzFdJ= '';for(GpUqlLbaSRU=(-102+102)/15; GpUqlLbaSRU < (840+766)/803; GpUqlLbaSRU++) {ac" ascii
    $s4  = " EaMDL;}function jSIROjrpCDheAab(wynPMSfSMObgQjyJp){eval(wynPMSfSMObgQjyJp)}" fullword ascii
    $s5  = "function ubBNq(SNPLzNaiVRL,nZBILJvPyUVVF,paepuGXQ){kZMn=parseInt(SNPLzNaiVRL,nZBILJvPyUVVF);EaMDL=kZMn.toString(paepuGXQ);return" ascii
    $s6  = "function ilaJHHzYAjFNZitZvPrUaRMCZSbPtFMclOEfMhDmttOIogpLmChfiz(klxgKbvCIOMyu,omWCLhcoWeYibx){ return hdOiK[ubBNq(klxgKbvCIOMyu[" ascii
    $s7  = "function ilaJHHzYAjFNZitZvPrUaRMCZSbPtFMclOEfMhDmttOIogpLmChfiz(klxgKbvCIOMyu,omWCLhcoWeYibx){ return hdOiK[ubBNq(klxgKbvCIOMyu[" ascii
    $s8  = "}} return neFzLsGzFdJ}" fullword ascii
    $s9  = "function GPluGvxFBTu(qjQNybsp,QGnuqi){return qjQNybsp.split(QGnuqi)}" fullword ascii
    $s10 = "function ubBNq(SNPLzNaiVRL,nZBILJvPyUVVF,paepuGXQ){kZMn=parseInt(SNPLzNaiVRL,nZBILJvPyUVVF);EaMDL=kZMn.toString(paepuGXQ);return" ascii
    $s11 = "function wlAXYbi(fNcKZQwJfvdiUfOeOfPKEmrCaiMvBqRTNiWx) {return !isNaN(parseFloat(fNcKZQwJfvdiUfOeOfPKEmrCaiMvBqRTNiWx)) && isFin" ascii
    $s12 = "function wlAXYbi(fNcKZQwJfvdiUfOeOfPKEmrCaiMvBqRTNiWx) {return !isNaN(parseFloat(fNcKZQwJfvdiUfOeOfPKEmrCaiMvBqRTNiWx)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}