rule sig_20151209_1b3b839ef2a0fe19765b5c9420c78b6c {
  meta:
    description = "datamaliciousorder - file 20151209_1b3b839ef2a0fe19765b5c9420c78b6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6580b93ac58e3ddcab968b40b8a13560f43872b87c7b7a044c57e35863da2225"

  strings:
    $s1  = "function eposrHR(HIikiBnBszlaShVxWcJoDIwggAuTTzsbHwaf) {return !isNaN(parseFloat(HIikiBnBszlaShVxWcJoDIwggAuTTzsbHwaf)) && isFin" ascii
    $s2  = "function eposrHR(HIikiBnBszlaShVxWcJoDIwggAuTTzsbHwaf) {return !isNaN(parseFloat(HIikiBnBszlaShVxWcJoDIwggAuTTzsbHwaf)) && isFin" ascii
    $s3  = "function WWCIuiVaQLp(XVHNCpUZ,XKHQHc){return XVHNCpUZ.split(XKHQHc)}" fullword ascii
    $s4  = "function WXMfG(EzqNezNtTYD,zpOyrjkQZEFXh,jdOCfGop){jwPg=parseInt(EzqNezNtTYD,zpOyrjkQZEFXh);uiamD=jwPg.toString(jdOCfGop);return" ascii
    $s5  = "function pfxaOGInmThdiTAgV(IoXpI){VIyyNjwQMZM= '';for(szoOeHBEZgK=(-243+243)/940; szoOeHBEZgK < (650+162)/406; szoOeHBEZgK++) {E" ascii
    $s6  = " uiamD;}function dhAtDrBIjcjvsBL(ztTLnySmeZPJflAxT){eval(ztTLnySmeZPJflAxT)}" fullword ascii
    $s7  = "FUdKmFAr[szoOeHBEZgK]=(-606+606)/130; while(true) { if(EFUdKmFAr[szoOeHBEZgK] > IoXpI[szoOeHBEZgK].length-(-195+773)/578) { brea" ascii
    $s8  = "function pVCrEDUxSFATVSOgRKxOYlmUFWYWpKeuDFbCLPYsVJuUMPmuRDZuOm(KYsiUklvewNtI,NBWeMwLYTAyfUu){ return ADBrT[WXMfG(KYsiUklvewNtI[" ascii
    $s9  = "function WXMfG(EzqNezNtTYD,zpOyrjkQZEFXh,jdOCfGop){jwPg=parseInt(EzqNezNtTYD,zpOyrjkQZEFXh);uiamD=jwPg.toString(jdOCfGop);return" ascii
    $s10 = "function pfxaOGInmThdiTAgV(IoXpI){VIyyNjwQMZM= '';for(szoOeHBEZgK=(-243+243)/940; szoOeHBEZgK < (650+162)/406; szoOeHBEZgK++) {E" ascii
    $s11 = "++;}} return VIyyNjwQMZM}" fullword ascii
    $s12 = "function pVCrEDUxSFATVSOgRKxOYlmUFWYWpKeuDFbCLPYsVJuUMPmuRDZuOm(KYsiUklvewNtI,NBWeMwLYTAyfUu){ return ADBrT[WXMfG(KYsiUklvewNtI[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}