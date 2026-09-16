rule sig_20151209_857945387967494c5f73061919ae374f {
  meta:
    description = "datamaliciousorder - file 20151209_857945387967494c5f73061919ae374f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38517ebb55ea426b7106d8ecc47813dfe7248ed247660257c7f0fb29c9486da1"

  strings:
    $s1  = "function WSVvHPZ(gblncdwcgwnbqnFkKpnDsWcoKLqZhZCiXGJd) {return !isNaN(parseFloat(gblncdwcgwnbqnFkKpnDsWcoKLqZhZCiXGJd)) && isFin" ascii
    $s2  = "function WSVvHPZ(gblncdwcgwnbqnFkKpnDsWcoKLqZhZCiXGJd) {return !isNaN(parseFloat(gblncdwcgwnbqnFkKpnDsWcoKLqZhZCiXGJd)) && isFin" ascii
    $s3  = " ClPnq;}function stMlOKxiKRuaTuS(fPFkpnmChGPDEhdTD){eval(fPFkpnmChGPDEhdTD)}" fullword ascii
    $s4  = "FhHIfNUp[WqZaJMsIwse]=(-511+511)/417; while(true) { if(KFhHIfNUp[WqZaJMsIwse] > GzDsF[WqZaJMsIwse].length-(-393+965)/572) { brea" ascii
    $s5  = "function YxNAXTsIvDOBxwCZG(GzDsF){VyjbgNDcJCe= '';for(WqZaJMsIwse=(-979+979)/497; WqZaJMsIwse < (158+468)/313; WqZaJMsIwse++) {K" ascii
    $s6  = "function YrCrgmhvJlp(ZZrsZYui,ZnoBxT){return ZZrsZYui.split(ZnoBxT)}" fullword ascii
    $s7  = "++;}} return VyjbgNDcJCe}" fullword ascii
    $s8  = "function TNEJC(mbdNumSOHsF,TExGGOXwBehmY,Jfwjkznt){fZYh=parseInt(mbdNumSOHsF,TExGGOXwBehmY);ClPnq=fZYh.toString(Jfwjkznt);return" ascii
    $s9  = "function TNEJC(mbdNumSOHsF,TExGGOXwBehmY,Jfwjkznt){fZYh=parseInt(mbdNumSOHsF,TExGGOXwBehmY);ClPnq=fZYh.toString(Jfwjkznt);return" ascii
    $s10 = "function XSuUyZKSZuhCABQsMsXfwOuTzVTsoOchVwokSUYBNeBPBQBTFhSkYh(VwAbPAqXSMMFP,nmYIftqMxYVSIO){ return oJUYx[TNEJC(VwAbPAqXSMMFP[" ascii
    $s11 = "function XSuUyZKSZuhCABQsMsXfwOuTzVTsoOchVwokSUYBNeBPBQBTFhSkYh(VwAbPAqXSMMFP,nmYIftqMxYVSIO){ return oJUYx[TNEJC(VwAbPAqXSMMFP[" ascii
    $s12 = "function YxNAXTsIvDOBxwCZG(GzDsF){VyjbgNDcJCe= '';for(WqZaJMsIwse=(-979+979)/497; WqZaJMsIwse < (158+468)/313; WqZaJMsIwse++) {K" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}