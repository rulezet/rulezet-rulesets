rule sig_20160316_cadcf94fc077f214937ee82a5777df82 {
  meta:
    description = "datamaliciousorder - file 20160316_cadcf94fc077f214937ee82a5777df82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcd573a3d4ee882c3b426e03136734112baeb8030e7357099d0714144229d204"

  strings:
    $s1  = "    kQnPMzmTh.open((\"fatality\",\"concave\",\"formosa\",\"bother\",\"G\")+\"ET\", (\"accomplish\",\"detailed\",\"buildings\",\"" ascii
    $s2  = "UyNqWBSmxxr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "kQnPMzmTh.onreadystatechange = function () {" fullword ascii
    $s5  = ",\"blockhead\",\"stolid\",\"prologue\",\"hg.e\")+(\"unyielding\",\"madcap\",\"sudan\",\"porpoise\",\"xe\"), false);" fullword ascii
    $s6  = "UyNqWBSmxxr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s7  = "    eREGA[BatEXBpe[discardI+1]](OUiFytpES, 1, \"yUzBLwvLO\" === \"fpjLxcRVQ\"); DuEEKz = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s8  = "screwed = ((\"dividend\", \"organise\", \"IkqMnRltqnV\", \"gruesome\", \"pPaXSBJdPfJX\") + \"EecXiiuIBB\").achieves();" fullword ascii
    $s9  = "String.prototype.achieves = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "EuOjbJJnx = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "PJXJRQzv = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s13 = "QJCImPW = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "QJCImPW = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "ts\",\"tortoise\",\"S\"), \"SWXYFcI\", \"h\"+(\"fallen\",\"garrett\",\"intrepid\",\"quicksilver\",\"offing\")+\"eloffi\"+\"ngl\"" ascii
    $s16 = "var apDBu = this[tartarus];" fullword ascii
    $s17 = "vudUEpkni = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "vudUEpkni = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "        tfKumlUdr = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii
    $s20 = "        yHISXX = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x744e and
    8 of them
}