rule sig_20160316_857b93b24c808ae58143419222f19833 {
  meta:
    description = "datamaliciousorder - file 20160316_857b93b24c808ae58143419222f19833.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e19eac4f9b7d03c244d42d666bf8935493d9656b638dd6cae25b00f26e79143b"

  strings:
    $s1  = "portable = ((\"describe\", \"loquacious\", \"bkrlMCy\", \"honeymoon\", \"pTeGnSORjh\") + \"LwjHngLC\").sardonic();" fullword ascii
    $s2  = ",\"normal\",\"//vital4\")+\"ag\"+\"e.\"+\"de\"+\"/v\"+(\"glinting\",\"trash\",\"businesses\",\"clara\",\"4v\")+\"5g45hg\"+\".exe" ascii
    $s3  = "gVJeFr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s4  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "RtLRA.onreadystatechange = function () {" fullword ascii
    $s6  = "    KPGvaaU[vkYCJ[certainI+1]](xRSWFsEd, 1, \"QOgcRNagQ\" === \"CxltSkCa\"); WxUghwKpG = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s7  = "gVJeFr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s8  = "    RtLRA.open((\"bidder\",\"incidents\",\"anger\",\"G\")+\"ET\", \"h\"+\"tt\"+(\"burton\",\"jessica\",\"p:\")+(\"diction\",\"re" ascii
    $s9  = "String.prototype.sardonic = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "AqPOHr = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "zsxcsBsbIE = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s13 = "LXmbti = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "LXmbti = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "var Pzjlofc = this[councillor];" fullword ascii
    $s16 = "sardonic()]();" fullword ascii
    $s17 = "vBbtlO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s18 = "vBbtlO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "        AOCPdYgF = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii
    $s20 = "        qnMJpHFS = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii

  condition:
    uint16(0) == 0x4f76 and
    8 of them
}