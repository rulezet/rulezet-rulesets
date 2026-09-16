rule sig_20151208_afcd6f266d034c64a5e6d5f1cd8c3a5d {
  meta:
    description = "datamaliciousorder - file 20151208_afcd6f266d034c64a5e6d5f1cd8c3a5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee8aef9562aad4753747fab6332f6247adef381f6167906331b8f1ebd241740c"

  strings:
    $s1  = "function wkxrmtq(TjVoyNXYCvaCpkXsIEqimCDUYXGWwFbuYmqD) {return !isNaN(parseFloat(TjVoyNXYCvaCpkXsIEqimCDUYXGWwFbuYmqD)) && isFin" ascii
    $s2  = "function wkxrmtq(TjVoyNXYCvaCpkXsIEqimCDUYXGWwFbuYmqD) {return !isNaN(parseFloat(TjVoyNXYCvaCpkXsIEqimCDUYXGWwFbuYmqD)) && isFin" ascii
    $s3  = "mqmBKiAHt[nZusfwrPSPh]=(-647+647)/812; while(true) { if(mqmBKiAHt[nZusfwrPSPh] > TiLNH[nZusfwrPSPh].length-(363+483)/846) { brea" ascii
    $s4  = "function ZMkrLvRZzqNSFtRmUkgmLEoyqZypHSoSAjLdypXzcRnkIhgLusxIDb(ZrarQybSnIjkY,OLLkBYSxgbTWIS){ return rqrEdxtKCzxHr[ZnBww(ZrarQy" ascii
    $s5  = "push(\"112\");W.push(\"43\");W.push(\"43\");W.push(\"41\");W.push(\"32\");W.push(\"32\");W.push(\"123\");W.push(\"13\");W.push(" ascii
    $s6  = "push(\"45\");r.push(\"105\");r.push(\"110\");r.push(\"99\");r.push(\"108\");r.push(\"117\");r.push(\"100\");r.push(\"101\");r.pu" ascii
    $s7  = "push(\"56\");r.push(\"48\");r.push(\"52\");r.push(\"54\");" fullword ascii
    $s8  = "push(\"83\");r.push(\"116\");r.push(\"114\");r.push(\"105\");r.push(\"110\");r.push(\"103\");r.push(\"115\");r.push(\"40\");r.pu" ascii
    $s9  = "push(\"34\");r.push(\"41\");r.push(\"43\");r.push(\"34\");r.push(\"112\");r.push(\"116\");r.push(\"46\");r.push(\"83\");r.push(" ascii
    $s10 = "+;}} return xksjBjlNWvL}" fullword ascii
    $s11 = "function BCoTZQJsSlCdaSTBX(TiLNH){xksjBjlNWvL= '';for(nZusfwrPSPh=(-544+544)/353; nZusfwrPSPh < (-477+879)/201; nZusfwrPSPh++) {" ascii
    $s12 = "var rqrEdxtKCzxHr=[];for(Upkemrv=(-930+930)/136;Upkemrv<(58409+343)/459;Upkemrv++){rqrEdxtKCzxHr[Upkemrv]=String.fromCharCode(Up" ascii
    $s13 = "function ZMkrLvRZzqNSFtRmUkgmLEoyqZypHSoSAjLdypXzcRnkIhgLusxIDb(ZrarQybSnIjkY,OLLkBYSxgbTWIS){ return rqrEdxtKCzxHr[ZnBww(ZrarQy" ascii
    $s14 = ";return ziyPn;}function rJJTkwBpbTTutsc(fNlMUNUJPHfCRIzjM){eval(fNlMUNUJPHfCRIzjM)}" fullword ascii
    $s15 = "kemrv)}function ZnBww(sxAtEerCZvh,rJEUOANGhwhxr,HLZEGIyI){PCmB=parseInt(sxAtEerCZvh,rJEUOANGhwhxr);ziyPn=PCmB.toString(HLZEGIyI)" ascii
    $s16 = "push(\"32\");W.push(\"32\");W.push(\"125\");W.push(\"59\");W.push(\"32\");W.push(\"77\");W.push(\"75\");W.push(\"103\");W.push(" ascii
    $s17 = "push(\"9\");W.push(\"105\");W.push(\"102\");W.push(\"32\");W.push(\"40\");W.push(\"99\");W.push(\"66\");W.push(\"32\");W.push(\"" ascii
    $s18 = "function BCoTZQJsSlCdaSTBX(TiLNH){xksjBjlNWvL= '';for(nZusfwrPSPh=(-544+544)/353; nZusfwrPSPh < (-477+879)/201; nZusfwrPSPh++) {" ascii
    $s19 = "push(\"114\");r.push(\"84\");r.push(\"32\");r.push(\"61\");r.push(\"32\");r.push(\"34\");r.push(\"50\");r.push(\"46\");r.push(\"" ascii
    $s20 = "function LsBLEPPOZgd(EpyKoDch,VBrQNC){return EpyKoDch.split(VBrQNC)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}