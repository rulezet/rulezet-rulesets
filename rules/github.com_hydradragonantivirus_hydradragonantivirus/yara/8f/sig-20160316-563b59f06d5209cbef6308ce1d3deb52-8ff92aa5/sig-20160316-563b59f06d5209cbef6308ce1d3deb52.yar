rule sig_20160316_563b59f06d5209cbef6308ce1d3deb52 {
  meta:
    description = "datamaliciousorder - file 20160316_563b59f06d5209cbef6308ce1d3deb52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65b644fecfe7a2f452064a5ea8c081ae0c85b0c730f5eff5683cd50629a8d712"

  strings:
    $s1  = "tunic = ((\"bolivia\", \"infections\", \"KROlvpLPuXw\", \"wampum\", \"pFhmuUFa\") + \"LddnUqmmpF\").incite();" fullword ascii
    $s2  = "rzoSPy = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s3  = "AEYJvkpPOds = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s4  = ",\"ebook\",\"ttp://\")+(\"modelling\",\"swiss\",\"vital4\")+\"ag\"+\"e.eu/v4v5g\"+\"45hg\"+(\"appeals\",\"trooper\",\"objecting" ascii
    $s5  = "dchcDMn.onreadystatechange = function () {" fullword ascii
    $s6  = "os[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s7  = "    KmqTnLnfI[BTXbRSrt[biographiesI+1]](sBbRkQuk, 1, \"QwyrIfDMMAs\" === \"lapxcdT\"); yuAOCkMgY = \" \\\"PSEUDO\\\": function( " ascii
    $s8  = "AEYJvkpPOds = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s9  = "xvegNDQ = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.incite = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "LTcbxbt = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s12 = "LTcbxbt = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "rgument ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity " ascii
    $s14 = "var VpfDsJPE = this[based];" fullword ascii
    $s15 = "based = BTXbRSrt[2+2+2].split(\"thirtyfour\").join(\"\");" fullword ascii
    $s16 = "DlxUVgwi = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s17 = "DlxUVgwi = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s18 = "    dchcDMn.open(\"G\"+(\"sites\",\"genetic\",\"additional\",\"weaver\",\"ET\"), (\"asset\",\"pascal\",\"oftentimes\",\"h\")+(\"" ascii
    $s19 = "        hWplxugvGSJ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        euhVcryRu = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii

  condition:
    uint16(0) == 0x414d and
    8 of them
}