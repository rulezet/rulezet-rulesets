rule sig_20160316_624f1efc9a7d2dd1b0f9537a323d6eb5 {
  meta:
    description = "datamaliciousorder - file 20160316_624f1efc9a7d2dd1b0f9537a323d6eb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39147b69fb9090d960e86d46b71034867e50e985d4e50f9d3eabf8698c4055ef"

  strings:
    $s1  = "Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s2  = "pJTtSWoTqAr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "YGKlYixd.onreadystatechange = function () {" fullword ascii
    $s4  = "    DsschI[yhJkn[extractionI+1]](feqlk, 1, \"YWQDrz\" === \"nnLVfXXvE\"); xGvXiM = \" \\\"PSEUDO\\\": function( pseudo, argument" ascii
    $s5  = "ate\",\"Ip\")+\"YtO\", \"Mbo\"+(\"verdant\",\"crony\",\"obySXboo\")+\"by\"+(\"distortion\",\"humanity\",\"MLbooby2\") + \".\"+(" ascii
    $s6  = "fighter = ((\"denmark\", \"lawlessness\", \"LFvLWSnzpe\", \"therapeutic\", \"pojbdyTTHDff\") + \"FeXUOACYNF\").apples();" fullword ascii
    $s7  = "pJTtSWoTqAr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "PtkjeCEvBF = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "ITRHIdm = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.apples = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "wBrqlwWPRq = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "wBrqlwWPRq = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "do-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom p" ascii
    $s14 = "ng\",\"xe\"), false);" fullword ascii
    $s15 = "var GiuNJhSH = this[packed];" fullword ascii
    $s16 = "XjjaTwCqkt = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s17 = "XjjaTwCqkt = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "    YGKlYixd.open(\"G\"+(\"occupations\",\"cumbersome\",\"ET\"), (\"felony\",\"marker\",\"lanky\",\"h\")+\"tt\"+\"p://vi\"+(\"de" ascii
    $s19 = "        LWfcstkwNi = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        JgdxyvB = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii

  condition:
    uint16(0) == 0x4745 and
    8 of them
}