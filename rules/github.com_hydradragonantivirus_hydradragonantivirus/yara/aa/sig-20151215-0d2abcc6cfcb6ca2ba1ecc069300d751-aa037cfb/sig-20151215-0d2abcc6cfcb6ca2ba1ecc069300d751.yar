rule sig_20151215_0d2abcc6cfcb6ca2ba1ecc069300d751 {
  meta:
    description = "datamaliciousorder - file 20151215_0d2abcc6cfcb6ca2ba1ecc069300d751.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4b7445e5513349b4995c0b9a7cd6533cc7b01b890f2330354821a089ce0a618"

  strings:
    $s1  = "ath.pow(Math.cos(163), 2) - 1)); while(true) { if(yykbbQbHg[jNLhHyYqYxU] > tWyNw[jNLhHyYqYxU].length-(223+677)/900) { break; } i" ascii
    $s2  = "function mSAZSDhzuwqKmCCII(tWyNw){umkXoxyakcu= t[1759];for(jNLhHyYqYxU=Math.round((Math.pow(Math.sin(156), 2) + Math.pow(Math.co" ascii
    $s3  = "w(Math.cos(693), 2) - 1)));} yykbbQbHg[jNLhHyYqYxU]++;}} return umkXoxyakcu}" fullword ascii
    $s4  = "function mSAZSDhzuwqKmCCII(tWyNw){umkXoxyakcu= t[1759];for(jNLhHyYqYxU=Math.round((Math.pow(Math.sin(156), 2) + Math.pow(Math.co" ascii
    $s5  = "function h(FdxYUJDbkYeE,nJsDqlTGdZRhaU){FdxYUJDbkYeE.push(nJsDqlTGdZRhaU);}function W9(HeOpqeQFDIYBuKYa){if(TkDwpqK(HeOpqeQFDIYB" ascii
    $s6  = "uKYa)) {return (String.fromCharCode(HeOpqeQFDIYBuKYa) + String.fromCharCode((6263+495)/109));}}" fullword ascii
    $s7  = "function TkDwpqK(iRsAmvCRJFhzgZCyjWVCEkUAJlSnqoTtkkCE) {return !isNaN(parseFloat(iRsAmvCRJFhzgZCyjWVCEkUAJlSnqoTtkkCE)) && isFin" ascii
    $s8  = "function TkDwpqK(iRsAmvCRJFhzgZCyjWVCEkUAJlSnqoTtkkCE) {return !isNaN(parseFloat(iRsAmvCRJFhzgZCyjWVCEkUAJlSnqoTtkkCE)) && isFin" ascii
    $s9  = " QjFDc;}function CLXkaoXAAFmEUbw(GxFqMUSXrrXpfXIwa,XqqXdWmZxcEgXzfLkxbygHjlQAvzhTEtyw,vQrZJIyrciGXiDEsVbnyqeobEYioYRYuptk){eval(" ascii
    $s10 = "function CLXkaoXAAFmEUbw(GxFqMUSXrrXpfXIwa){eval(GxFqMUSXrrXpfXIwa)}" fullword ascii
    $s11 = "function h(FdxYUJDbkYeE,nJsDqlTGdZRhaU){FdxYUJDbkYeE.push(nJsDqlTGdZRhaU);}function W9(HeOpqeQFDIYBuKYa){if(TkDwpqK(HeOpqeQFDIYB" ascii
    $s12 = "function sDeUoPormlK(ZosQwLBM,ipYzUS){return ZosQwLBM.split(ipYzUS)}" fullword ascii
    $s13 = "function GRdfLoXOqxMRQkegyMgtZsgqdMXYLXsoPXcppGJopEfLFHVyJarxny(clDHvMChWGOSu,LrDmIDjvxtoHjh){ return RbpOPTM[iYjfDQxB[hUfuI(clD" ascii
    $s14 = "function GRdfLoXOqxMRQkegyMgtZsgqdMXYLXsoPXcppGJopEfLFHVyJarxny(clDHvMChWGOSu,LrDmIDjvxtoHjh){ return RbpOPTM[iYjfDQxB[hUfuI(clD" ascii
    $s15 = "function hUfuI(TKZaINUOGwV,ntZaecRcSOmUp,JmfiRTib){jEak=parseInt(TKZaINUOGwV,ntZaecRcSOmUp);QjFDc=jEak.toString(JmfiRTib);return" ascii
    $s16 = "var t=new Array();" fullword ascii
    $s17 = "function hUfuI(TKZaINUOGwV,ntZaecRcSOmUp,JmfiRTib){jEak=parseInt(TKZaINUOGwV,ntZaecRcSOmUp);QjFDc=jEak.toString(JmfiRTib);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}