rule sig_20160316_b92457b0d49c303e26e5db4b1bdaafbb {
  meta:
    description = "datamaliciousorder - file 20160316_b92457b0d49c303e26e5db4b1bdaafbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c6fceb704cabfb3849ce619565c04998577c00212532eb49d7581fdb60ba605"

  strings:
    $s1  = "    zpIgKMyOu.open(\"G\"+(\"entrepreneurs\",\"pretender\",\"fortynine\",\"homemade\",\"ET\"), \"http:\"+(\"quality\",\"firstborn" ascii
    $s2  = "BHlJhfdO = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s3  = "sition\",\"//what\")+(\"mahdi\",\"restored\",\"discrimination\",\"skv.co\")+\"m/v4v5g45hg.exe\", false);" fullword ascii
    $s4  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "zpIgKMyOu.onreadystatechange = function () {" fullword ascii
    $s6  = "    IpHLMS[YAspgWz[watcherI+1]](YJtyJ, 1, \"TzpsMzdwhqw\" === \"thuQluBEMJ\"); hiQuynDim = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s7  = "BHlJhfdO = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s8  = "XBNoAwF = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "String.prototype.experiencing = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "LqcYprJQvU = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s12 = "QrxshX = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "QrxshX = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "tradesman = ((\"unalloyed\", \"wright\", \"BVgXczicCe\", \"annual\", \"peCkMmQTyUq\") + \"KieYhcaqbi\").experiencing();" fullword ascii
    $s15 = "inAkwRWg = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s16 = "inAkwRWg = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s17 = "        sRUnffPEbF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.u" ascii
    $s18 = "        ztKeEzIkIV = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s19 = "        sRUnffPEbF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.u" ascii
    $s20 = "        NGphzqYu = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii

  condition:
    uint16(0) == 0x5477 and
    8 of them
}