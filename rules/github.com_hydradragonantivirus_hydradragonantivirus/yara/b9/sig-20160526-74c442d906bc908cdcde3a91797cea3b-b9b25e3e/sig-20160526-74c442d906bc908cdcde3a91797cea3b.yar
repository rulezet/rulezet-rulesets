rule sig_20160526_74c442d906bc908cdcde3a91797cea3b {
  meta:
    description = "datamaliciousorder - file 20160526_74c442d906bc908cdcde3a91797cea3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dfa83b12abad4fd61bac35b1d0af23e6d3d599034b9bde1b8880acd5b7550cf"

  strings:
    $s1  = ") + Math.pow(Math.cos(912), 2) - 1))-609) | keYEzTYbdyamZEeCuhNB;CdGxtluUNwDf = HxzWlMyeSOqmI>> (743 + Math.round((Math.pow(Math" ascii
    $s2  = "function ycTkTpXA(LdGSciDAPaVnY) {var xsRRHWkpKUW = kFrbdpZ.join(fOYeBzSotwtHO[0]);var CdGxtluUNwDf, CcirmwGBPV, XVfKyEbMw, emsc" ascii
    $s3  = "h.round((Math.pow(Math.sin(504), 2) + Math.pow(Math.cos(504), 2) - 1))-939)) unsQBeQdTuoVUBxEAwly += nc(CdGxtluUNwDf);else if (k" ascii
    $s4  = "function pOHol(YFYPaGgnsfl,aRYJnYmpTSYwojAsIsDIXhtq){return YFYPaGgnsfl.charAt(aRYJnYmpTSYwojAsIsDIXhtq);}" fullword ascii
    $s5  = "function nc(irXNzeHZOMMhsaKn){return String.fromCharCode(irXNzeHZOMMhsaKn);}" fullword ascii
    $s6  = "ly += ExopZUoJXQqhpQG(CdGxtluUNwDf, CcirmwGBPV);else unsQBeQdTuoVUBxEAwly += TVTwiQNjizfvKAMhSAjDF(CdGxtluUNwDf, CcirmwGBPV, XVf" ascii
    $s7  = "KyEbMw);} while (TZDZVBYPYLYeDqWfNkrnsXIE < LdGSciDAPaVnY.length);return unsQBeQdTuoVUBxEAwly;}" fullword ascii
    $s8  = "function ExopZUoJXQqhpQG(BRQdqTyLYDVIYkMy,tXRVE){return String.fromCharCode(BRQdqTyLYDVIYkMy,tXRVE);}" fullword ascii
    $s9  = "function vcFisAByNQLAnCFUSnjYJetC(pZFbMP,OPnbyhF){return pZFbMP.indexOf(OPnbyhF);}" fullword ascii
    $s10 = "function TVTwiQNjizfvKAMhSAjDF(CThFU,SQULSPUiPfODMmmBMzxylTQD,sbbZzzuCrfITdokyglqclViI){return String.fromCharCode(CThFU,SQULSPU" ascii
    $s11 = "function ycTkTpXA(LdGSciDAPaVnY) {var xsRRHWkpKUW = kFrbdpZ.join(fOYeBzSotwtHO[0]);var CdGxtluUNwDf, CcirmwGBPV, XVfKyEbMw, emsc" ascii
    $s12 = "function TVTwiQNjizfvKAMhSAjDF(CThFU,SQULSPUiPfODMmmBMzxylTQD,sbbZzzuCrfITdokyglqclViI){return String.fromCharCode(CThFU,SQULSPU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}