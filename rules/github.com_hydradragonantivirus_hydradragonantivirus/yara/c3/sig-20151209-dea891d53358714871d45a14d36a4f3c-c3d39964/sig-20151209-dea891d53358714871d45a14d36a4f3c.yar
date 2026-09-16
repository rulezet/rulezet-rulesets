rule sig_20151209_dea891d53358714871d45a14d36a4f3c {
  meta:
    description = "datamaliciousorder - file 20151209_dea891d53358714871d45a14d36a4f3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81204487fc962c49fc11eb084cf1541886e5b8aa7c82a79d9c10758f294ea97d"

  strings:
    $s1  = "function OcFgapD(FZYvpEQcTpJjBIwZVUbaWpiccxlGKXJKjuUy) {return !isNaN(parseFloat(FZYvpEQcTpJjBIwZVUbaWpiccxlGKXJKjuUy)) && isFin" ascii
    $s2  = "function OcFgapD(FZYvpEQcTpJjBIwZVUbaWpiccxlGKXJKjuUy) {return !isNaN(parseFloat(FZYvpEQcTpJjBIwZVUbaWpiccxlGKXJKjuUy)) && isFin" ascii
    $s3  = "function nqviv(ROeqeHyDLtK,EpAYKKMeVlcsr,jMUXKycz){FTmr=parseInt(ROeqeHyDLtK,EpAYKKMeVlcsr);ignjP=FTmr.toString(jMUXKycz);return" ascii
    $s4  = "function FywPauniIbjaADBEDcRJBpvjTrnHteLBByExbfVNJYqBoelQlHIAip(ixUudsFgkXnZD,UMCCRVuEasNMyA){ return NIXTK[nqviv(ixUudsFgkXnZD[" ascii
    $s5  = " ignjP;}function khhZOivGBJHWuKe(uryUtAzhbsuPSKrOj){eval(uryUtAzhbsuPSKrOj)}" fullword ascii
    $s6  = "function gamsrticfvPmzjBkK(JaKLZ){EtcbZDNUydw= '';for(kDdlHgUKoiO=(-410+410)/284; kDdlHgUKoiO < (1258+562)/910; kDdlHgUKoiO++) {" ascii
    $s7  = "jXUaXmLwu[kDdlHgUKoiO]=(-872+872)/323; while(true) { if(jXUaXmLwu[kDdlHgUKoiO] > JaKLZ[kDdlHgUKoiO].length-(-26+906)/880) { brea" ascii
    $s8  = "function FywPauniIbjaADBEDcRJBpvjTrnHteLBByExbfVNJYqBoelQlHIAip(ixUudsFgkXnZD,UMCCRVuEasNMyA){ return NIXTK[nqviv(ixUudsFgkXnZD[" ascii
    $s9  = "function BzDuIrpIdCL(pPJOWlzn,RZaLdB){return pPJOWlzn.split(RZaLdB)}" fullword ascii
    $s10 = "++;}} return EtcbZDNUydw}" fullword ascii
    $s11 = "function nqviv(ROeqeHyDLtK,EpAYKKMeVlcsr,jMUXKycz){FTmr=parseInt(ROeqeHyDLtK,EpAYKKMeVlcsr);ignjP=FTmr.toString(jMUXKycz);return" ascii
    $s12 = "function gamsrticfvPmzjBkK(JaKLZ){EtcbZDNUydw= '';for(kDdlHgUKoiO=(-410+410)/284; kDdlHgUKoiO < (1258+562)/910; kDdlHgUKoiO++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}