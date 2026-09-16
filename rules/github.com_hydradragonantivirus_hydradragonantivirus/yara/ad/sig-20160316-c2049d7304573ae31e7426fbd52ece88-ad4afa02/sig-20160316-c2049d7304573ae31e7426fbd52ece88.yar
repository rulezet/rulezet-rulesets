rule sig_20160316_c2049d7304573ae31e7426fbd52ece88 {
  meta:
    description = "datamaliciousorder - file 20160316_c2049d7304573ae31e7426fbd52ece88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "900b9c53eb266f2ebc97cc30d7f6d4e1b7592b5604e6062a57c380f87850c9f9"

  strings:
    $s1  = "BICHJGxHz = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "RMEcJ.onreadystatechange = function () {" fullword ascii
    $s4  = "refine = ((\"divided\", \"shock\", \"YdKNjGzd\", \"flakes\", \"pXVHguQGgL\") + \"QooIkuorW\").tuning();" fullword ascii
    $s5  = "BICHJGxHz = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "    ENcRy[TpkaMIhq[determineI+1]](VaFbzrWLq, 1, \"MBKbcjSOGWI\" === \"iBEJmzhR\"); dOyvSzx = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s7  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s8  = "hIipns = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "var TpkaMIhq = [\"M\"+(\"criticism\",\"naming\",\"myrtle\",\"threequarter\",\"gn\")+\"lq\"+\"Fr\", (\"notoriously\",\"completing" ascii
    $s10 = "String.prototype.tuning = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "pHHQejdN = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s13 = "YvJzuJOzO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s14 = "YvJzuJOzO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s15 = "    RMEcJ.open((\"tortoise\",\"promoting\",\"G\")+\"ET\", \"h\"+\"tt\"+\"p:\"+\"//\"+\"vi\"+\"p-sh\"+\"ap\"+(\"roster\",\"arthri" ascii
    $s16 = "/v4v\"+\"5g45hg\"+\".e\"+\"xe\", false);" fullword ascii
    $s17 = "var uRriyB = this[atheism];" fullword ascii
    $s18 = "atheism = TpkaMIhq[2+2+2].split(\"magnet\").join(\"\");" fullword ascii
    $s19 = "uBkoqkEXpO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s20 = "uBkoqkEXpO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii

  condition:
    uint16(0) == 0x494f and
    8 of them
}