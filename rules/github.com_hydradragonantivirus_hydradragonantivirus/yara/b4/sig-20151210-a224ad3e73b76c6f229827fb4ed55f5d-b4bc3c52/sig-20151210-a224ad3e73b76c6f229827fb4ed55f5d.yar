rule sig_20151210_a224ad3e73b76c6f229827fb4ed55f5d {
  meta:
    description = "datamaliciousorder - file 20151210_a224ad3e73b76c6f229827fb4ed55f5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0042686df068b567d98e5c3729c9e8f64a1fec4ff429e4fb4755f9be7ec9a7fd"

  strings:
    $s1  = "function lCoLj(hcKcjUEYWzN,cedbWQDhhPoJh,sjypwVmQ){jBtJ=parseInt(hcKcjUEYWzN,cedbWQDhhPoJh);clQVj=jBtJ.toString(sjypwVmQ);return" ascii
    $s2  = "function isYevJQ(MWcuQKmoIBycgxBXexyToXHmPkdrLPQYaGFQ) {return !isNaN(parseFloat(MWcuQKmoIBycgxBXexyToXHmPkdrLPQYaGFQ)) && isFin" ascii
    $s3  = " clQVj;}function SZMvhWWwwSjEsUF(dCSbHcprTMPgAdrGd){eval(dCSbHcprTMPgAdrGd)}" fullword ascii
    $s4  = "function isYevJQ(MWcuQKmoIBycgxBXexyToXHmPkdrLPQYaGFQ) {return !isNaN(parseFloat(MWcuQKmoIBycgxBXexyToXHmPkdrLPQYaGFQ)) && isFin" ascii
    $s5  = "function lCoLj(hcKcjUEYWzN,cedbWQDhhPoJh,sjypwVmQ){jBtJ=parseInt(hcKcjUEYWzN,cedbWQDhhPoJh);clQVj=jBtJ.toString(sjypwVmQ);return" ascii
    $s6  = "function hJFjUZbDFlqfXgDLHeUFDmklWjvfKloJoIwFJboSoDbDTrPrpifhqj(gsluQzUuHUlfk,DonJkBPnCUKcLY){ return rEeZZ[lCoLj(gsluQzUuHUlfk[" ascii
    $s7  = "TNcNAPid[xJHdxfoFRle]=(-545+545)/85; while(true) { if(eTNcNAPid[xJHdxfoFRle] > JqoOm[xJHdxfoFRle].length-(556+91)/647) { break; " ascii
    $s8  = "function RcUNRKsBRCqUWtQKU(JqoOm){euZvDnDDKYZ= '';for(xJHdxfoFRle=(-465+465)/420; xJHdxfoFRle < (630+740)/685; xJHdxfoFRle++) {e" ascii
    $s9  = "function hJFjUZbDFlqfXgDLHeUFDmklWjvfKloJoIwFJboSoDbDTrPrpifhqj(gsluQzUuHUlfk,DonJkBPnCUKcLY){ return rEeZZ[lCoLj(gsluQzUuHUlfk[" ascii
    $s10 = "function jebDgQFCWJu(MpCBFaKa,lnOIlN){return MpCBFaKa.split(lnOIlN)}" fullword ascii
    $s11 = "function RcUNRKsBRCqUWtQKU(JqoOm){euZvDnDDKYZ= '';for(xJHdxfoFRle=(-465+465)/420; xJHdxfoFRle < (630+740)/685; xJHdxfoFRle++) {e" ascii
    $s12 = "}} return euZvDnDDKYZ}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}