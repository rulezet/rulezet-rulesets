rule sig_20160316_7dd9d905162377cb30d4d0b5dab0b25e {
  meta:
    description = "datamaliciousorder - file 20160316_7dd9d905162377cb30d4d0b5dab0b25e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89acfaa2d06447b7a7959119371cfbcc2357dfe8099f434cc158c0146992fd5a"

  strings:
    $s1  = "    gQbOAvk.open(\"G\"+(\"animosity\",\"urban\",\"terrible\",\"ET\"), \"http://winj\"+\"oytechnolo\"+\"gies\"+\".com\"+\"/v4v5g" ascii
    $s2  = "te\",\"profuse\",\"whiting\",\".exe\"), false);" fullword ascii
    $s3  = "FJqrdcNKy = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s4  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "gQbOAvk.onreadystatechange = function () {" fullword ascii
    $s6  = "cpick\")+(\"prostitution\",\"dialects\",\"campfire\",\"agreements\",\"up\")+\"ri\"+\"pt\"+(\"harvard\",\"italic\",\"pickup.\") +" ascii
    $s7  = "    KOBzWdlst[VogojAsRy[whereI+1]](thfSnLN, 1, \"xHLnJbAti\" === \"nvovikR\"); VVPfDaJ = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s8  = "FJqrdcNKy = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s9  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "mlFwDSBLrU = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "String.prototype.symphony = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "kWHXJxmc = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s13 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s14 = "vsbWLnqUnEP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s15 = "vsbWLnqUnEP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s16 = "var OkBSdhB = this[recovered];" fullword ascii
    $s17 = "doTAsEj = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "doTAsEj = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        KswseJgF = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii
    $s20 = "        SLDCrkfU = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii

  condition:
    uint16(0) == 0x6f41 and
    8 of them
}