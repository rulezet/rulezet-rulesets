rule sig_20151208_ee12dcbc339f74376ae5ed51e8e152f5 {
  meta:
    description = "datamaliciousorder - file 20151208_ee12dcbc339f74376ae5ed51e8e152f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f650dcb6876d6c6738c7a838f4af98c34240d979c4d569c32168026e9e1be6f"

  strings:
    $s1  = "function almzczU(ebqlTNfuvhiYfOeEHgWjnRfTtDiyNRLCQcFm) {return !isNaN(parseFloat(ebqlTNfuvhiYfOeEHgWjnRfTtDiyNRLCQcFm)) && isFin" ascii
    $s2  = "function almzczU(ebqlTNfuvhiYfOeEHgWjnRfTtDiyNRLCQcFm) {return !isNaN(parseFloat(ebqlTNfuvhiYfOeEHgWjnRfTtDiyNRLCQcFm)) && isFin" ascii
    $s3  = "push(\"61\");i.push(\"32\");i.push(\"34\");i.push(\"37\");i.push(\"84\");i.push(\"69\");i.push(\"77\");i.push(\"80\");i.push(\"3" ascii
    $s4  = "push(\"53\");Q.push(\"52\");Q.push(\"50\");Q.push(\"57\");Q.push(\"52\");Q.push(\"109\");Q.push(\"78\");Q.push(\"42\");Q.push(\"" ascii
    $s5  = "function vwuZPywlwDQkptHjd(KuRgk){iDNiZrEEBbt= '';for(XvhrLlbMbEW=(-558+558)/658; XvhrLlbMbEW < (1862+84)/973; XvhrLlbMbEW++) {U" ascii
    $s6  = "push(\"114\");Q.push(\"101\");Q.push(\"97\");Q.push(\"107\");Q.push(\"59\");Q.push(\"13\");Q.push(\"10\");Q.push(\"32\");Q.push(" ascii
    $s7  = "var izmiDGgHGFzTW=[];for(VqbFmLM=(-913+913)/303;VqbFmLM<(28846+338)/228;VqbFmLM++){izmiDGgHGFzTW[VqbFmLM]=String.fromCharCode(Vq" ascii
    $s8  = "KwAVQnrG[XvhrLlbMbEW]=(-312+312)/86; while(true) { if(UKwAVQnrG[XvhrLlbMbEW] > KuRgk[XvhrLlbMbEW].length-(287+196)/483) { break;" ascii
    $s9  = "function CCilpStVZKtjhfhQaxzLWneJDfpOnilCsIspIIHeKuYVXKLZJGZZno(kECTbFNobOibq,eXAdZStiPeAaed){ return izmiDGgHGFzTW[ljjLI(kECTbF" ascii
    $s10 = "function CCilpStVZKtjhfhQaxzLWneJDfpOnilCsIspIIHeKuYVXKLZJGZZno(kECTbFNobOibq,eXAdZStiPeAaed){ return izmiDGgHGFzTW[ljjLI(kECTbF" ascii
    $s11 = "push(\"32\");Q.push(\"13\");Q.push(\"10\");Q.push(\"9\");Q.push(\"9\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32" ascii
    $s12 = "push(\"32\");i.push(\"61\");i.push(\"32\");i.push(\"34\");i.push(\"65\");i.push(\"68\");i.push(\"79\");i.push(\"68\");i.push(\"3" ascii
    $s13 = "function OcYnIxDAeEn(VSFXUPSs,dOoEpv){return VSFXUPSs.split(dOoEpv)}" fullword ascii
    $s14 = "push(\"99\");i.push(\"61\");i.push(\"74\");i.push(\"101\");i.push(\"66\");i.push(\"59\");i.push(\"32\");i.push(\"99\");i.push(\"" ascii
    $s15 = "push(\"47\");i.push(\"42\");i.push(\"88\");i.push(\"56\");i.push(\"49\");i.push(\"77\");i.push(\"54\");i.push(\"51\");i.push(\"5" ascii
    $s16 = "push(\"40\");Q.push(\"85\");Q.push(\"80\");Q.push(\"41\");Q.push(\"32\");Q.push(\"32\");Q.push(\"123\");Q.push(\"13\");Q.push(\"" ascii
    $s17 = "push(\"99\");Q.push(\"97\");Q.push(\"116\");Q.push(\"99\");Q.push(\"104\");Q.push(\"32\");Q.push(\"40\");Q.push(\"85\");Q.push(" ascii
    $s18 = "bFmLM)}function ljjLI(KFLqoDyUVVs,RlgoDnmfFMXeh,NnkURhtz){oEYn=parseInt(KFLqoDyUVVs,RlgoDnmfFMXeh);muAGH=oEYn.toString(NnkURhtz)" ascii
    $s19 = "function vwuZPywlwDQkptHjd(KuRgk){iDNiZrEEBbt= '';for(XvhrLlbMbEW=(-558+558)/658; XvhrLlbMbEW < (1862+84)/973; XvhrLlbMbEW++) {U" ascii
    $s20 = "}} return iDNiZrEEBbt}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}