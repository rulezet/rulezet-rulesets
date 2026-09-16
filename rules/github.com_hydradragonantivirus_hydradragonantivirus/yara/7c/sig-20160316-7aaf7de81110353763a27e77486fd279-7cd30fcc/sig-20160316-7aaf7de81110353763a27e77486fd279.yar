rule sig_20160316_7aaf7de81110353763a27e77486fd279 {
  meta:
    description = "datamaliciousorder - file 20160316_7aaf7de81110353763a27e77486fd279.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c18d12b0fe2e24a9a92da5b6a39712119a6061b097f60d0a71a0b75b3d1ab6b"

  strings:
    $s1  = "GspwnhMKG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "TNlRDbTPU.onreadystatechange = function () {" fullword ascii
    $s4  = "    BrsqX[hchqrcLCC[figurativelyI+1]](PDBTL, 1, \"ctgcChR\" === \"jJINmnDpi\"); YWQRCK = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s5  = "GspwnhMKG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "kCJaecWksFG = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s7  = "String.prototype.cooler = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "YceTeQv = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s10 = "HrLeFINhWM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s11 = "HrLeFINhWM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "    TNlRDbTPU.open((\"affably\",\"morphia\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//webm\"+\"ai\"+\"l.\"+\"p5\"+\"5.\"+\"be/v\"+\"4v\"" ascii
    $s13 = "fly\",\"hg\")+\".e\"+\"xe\", false);" fullword ascii
    $s14 = "sunshine = hchqrcLCC[2+2+2].split(\"mystified\").join(\"\");" fullword ascii
    $s15 = "multiplication = ((\"lexicon\", \"deathbed\", \"skGSBT\", \"voiceless\", \"pqYGlWkc\") + \"KRmOOszp\").cooler();" fullword ascii
    $s16 = "var RRFevpbcR = this[sunshine];" fullword ascii
    $s17 = "RYttdkEqk = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "RYttdkEqk = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "        IpHkBQsQ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii
    $s20 = "        EguYeqN = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii

  condition:
    uint16(0) == 0x654b and
    8 of them
}