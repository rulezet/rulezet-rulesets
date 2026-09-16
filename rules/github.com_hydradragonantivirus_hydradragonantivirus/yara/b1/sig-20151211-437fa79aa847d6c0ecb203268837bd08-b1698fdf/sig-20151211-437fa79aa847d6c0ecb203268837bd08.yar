rule sig_20151211_437fa79aa847d6c0ecb203268837bd08 {
  meta:
    description = "datamaliciousorder - file 20151211_437fa79aa847d6c0ecb203268837bd08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36ef43c9927e1bbeb25159ab4329d24c264d9da6c3b6e20eae653aaae9703eeb"

  strings:
    $s1  = "SPYxUUxhT[oZVQWUCGdUd]=(-17+17)/260; while(true) { if(SPYxUUxhT[oZVQWUCGdUd] > kUeCN[oZVQWUCGdUd].length-(-670+686)/16) { break;" ascii
    $s2  = "function hWvFijq(iwraFPfzvwelZmYbgIRbwANBCLdpibSbQFYs) {return !isNaN(parseFloat(iwraFPfzvwelZmYbgIRbwANBCLdpibSbQFYs)) && isFin" ascii
    $s3  = "function hWvFijq(iwraFPfzvwelZmYbgIRbwANBCLdpibSbQFYs) {return !isNaN(parseFloat(iwraFPfzvwelZmYbgIRbwANBCLdpibSbQFYs)) && isFin" ascii
    $s4  = "function vMzDmCYLqXOqkPatb(kUeCN){zDxmpEcMrAz= '';oZVQWUCGdUd=(-413+413)/241; while(true){if(oZVQWUCGdUd >= (-533+597)/32)break;" ascii
    $s5  = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "}oZVQWUCGdUd++;} return zDxmpEcMrAz}" fullword ascii
    $s7  = " nGNLG;}function WuRDMvzdKNYieJd(sETKUaRqdSolrIsbA){eval(sETKUaRqdSolrIsbA)}" fullword ascii
    $s8  = "function vMzDmCYLqXOqkPatb(kUeCN){zDxmpEcMrAz= '';oZVQWUCGdUd=(-413+413)/241; while(true){if(oZVQWUCGdUd >= (-533+597)/32)break;" ascii
    $s9  = "var J=new Array(\"29\",\"26\",\"27\",\"27\",\"2d\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "function WuZLTrRxhsG(DKQTifqu,GfKyBO){return DKQTifqu.split(GfKyBO)}" fullword ascii
    $s11 = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "var J=new Array(\"29\",\"26\",\"27\",\"27\",\"2d\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "function iTYXpXQsmqdpToWxxBJzJPmuEOXRzAHDItGbajLJbAEDRGwWlpcduK(cqmsXJjWUJInQ,TyQrKQYjlspiIj){ return tORfn[LhcAi(cqmsXJjWUJInQ[" ascii
    $s14 = "function LhcAi(FleBkdLQtHd,dSbvXQPNLCTvP,DmRclcMv){VNby=parseInt(FleBkdLQtHd,dSbvXQPNLCTvP);nGNLG=VNby.toString(DmRclcMv);return" ascii
    $s15 = "function iTYXpXQsmqdpToWxxBJzJPmuEOXRzAHDItGbajLJbAEDRGwWlpcduK(cqmsXJjWUJInQ,TyQrKQYjlspiIj){ return tORfn[LhcAi(cqmsXJjWUJInQ[" ascii
    $s16 = "function LhcAi(FleBkdLQtHd,dSbvXQPNLCTvP,DmRclcMv){VNby=parseInt(FleBkdLQtHd,dSbvXQPNLCTvP);nGNLG=VNby.toString(DmRclcMv);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}