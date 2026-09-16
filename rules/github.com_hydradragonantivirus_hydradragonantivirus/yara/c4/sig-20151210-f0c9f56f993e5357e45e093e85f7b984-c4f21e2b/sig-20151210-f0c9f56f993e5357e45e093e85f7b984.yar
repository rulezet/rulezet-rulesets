rule sig_20151210_f0c9f56f993e5357e45e093e85f7b984 {
  meta:
    description = "datamaliciousorder - file 20151210_f0c9f56f993e5357e45e093e85f7b984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8743cc87d05c9acbf0d13162daef00bf4c6fb801515a43bba0acd55d70f81a3"

  strings:
    $s1  = "function nztlRGK(LwDVmjriEIemkhunzIzycRrtKHpzmRPLTAFj) {return !isNaN(parseFloat(LwDVmjriEIemkhunzIzycRrtKHpzmRPLTAFj)) && isFin" ascii
    $s2  = "function nztlRGK(LwDVmjriEIemkhunzIzycRrtKHpzmRPLTAFj) {return !isNaN(parseFloat(LwDVmjriEIemkhunzIzycRrtKHpzmRPLTAFj)) && isFin" ascii
    $s3  = "function pRTFnhbdUOqNQbkMhitEJzdeKmZaQAmazKdsvxQKDBRCVFUiLqIxyM(tJRNYTAEDtdpI,hRbrtsNssXoelN){ return RxVAtwDlJyYNc[ojBYB(tJRNYT" ascii
    $s4  = "function sxPZvTROIHV(RdfUDzqY,ibTAIx){return RdfUDzqY.split(ibTAIx)}" fullword ascii
    $s5  = "XupqPLS=(-980+980)/814;while(true){if(XupqPLS>=(114912+416)/901){break;}RxVAtwDlJyYNc[XupqPLS]=String.fromCharCode(XupqPLS);Xupq" ascii
    $s6  = "function ojBYB(DYNjeuqGKtv,MCwwYOYeNpUJT,nimSTsQO){uTtq=parseInt(DYNjeuqGKtv,MCwwYOYeNpUJT);HYlYL=uTtq.toString(nimSTsQO);return" ascii
    $s7  = " HYlYL;}function YJSObZtJHzFzNcf(tzOCkPWhJqlWUByKE){eval(tzOCkPWhJqlWUByKE)}" fullword ascii
    $s8  = "function lJPcVIxfVcVQcQiTR(WHAUJ){owGijiBQdyi= '';for(xfRDipOpJDP=(-152+152)/172; xfRDipOpJDP < (970+472)/721; xfRDipOpJDP++) {r" ascii
    $s9  = "XupqPLS=(-980+980)/814;while(true){if(XupqPLS>=(114912+416)/901){break;}RxVAtwDlJyYNc[XupqPLS]=String.fromCharCode(XupqPLS);Xupq" ascii
    $s10 = "function ojBYB(DYNjeuqGKtv,MCwwYOYeNpUJT,nimSTsQO){uTtq=parseInt(DYNjeuqGKtv,MCwwYOYeNpUJT);HYlYL=uTtq.toString(nimSTsQO);return" ascii
    $s11 = "DqipZeEn[xfRDipOpJDP]=(-388+388)/694; while(true) { if(rDqipZeEn[xfRDipOpJDP] > WHAUJ[xfRDipOpJDP].length-(110+745)/855) { break" ascii
    $s12 = "function lJPcVIxfVcVQcQiTR(WHAUJ){owGijiBQdyi= '';for(xfRDipOpJDP=(-152+152)/172; xfRDipOpJDP < (970+472)/721; xfRDipOpJDP++) {r" ascii
    $s13 = "function pRTFnhbdUOqNQbkMhitEJzdeKmZaQAmazKdsvxQKDBRCVFUiLqIxyM(tJRNYTAEDtdpI,hRbrtsNssXoelN){ return RxVAtwDlJyYNc[ojBYB(tJRNYT" ascii
    $s14 = "+;}} return owGijiBQdyi}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}