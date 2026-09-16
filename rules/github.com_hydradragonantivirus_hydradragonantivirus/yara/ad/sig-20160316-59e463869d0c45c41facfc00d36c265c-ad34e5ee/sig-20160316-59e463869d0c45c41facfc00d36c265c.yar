rule sig_20160316_59e463869d0c45c41facfc00d36c265c {
  meta:
    description = "datamaliciousorder - file 20160316_59e463869d0c45c41facfc00d36c265c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d73e53461d69ee5f8fc6b7e44e042ea54971874f0503b410b055487a5ac6f48"

  strings:
    $s1  = "    zHhrEuhE.open((\"squirt\",\"stuffy\",\"G\")+\"ET\", \"h\"+\"tt\"+\"p:\"+(\"nicaragua\",\"aside\",\"abstracted\",\"revisit\"," ascii
    $s2  = "DubqabnH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s3  = "sight\",\"rosebud\",\"narrate\",\"45\")+(\"appearing\",\"incomplete\",\"hg.e\")+(\"pleasure\",\"jockey\",\"xe\"), false);" fullword ascii
    $s4  = "seudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "zHhrEuhE.onreadystatechange = function () {" fullword ascii
    $s6  = "    jaEychjO[cjhdKvLu[civilianI+1]](GxnkYsJim, 1, \"MRSAyInA\" === \"EEYzsikcF\"); zWcIaeTB = \" \\\"PSEUDO\\\": function( pseud" ascii
    $s7  = "DubqabnH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s8  = "institute = ((\"contumely\", \"overturn\", \"MouXgim\", \"nudity\", \"pFJXCPiAXpt\") + \"fpUsHWRW\").funeral();" fullword ascii
    $s9  = "EUDmfarU = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "cbVvBwYfNCb = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.funeral = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "ezJyPDlCTt = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "nt ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in ca" ascii
    $s14 = "ezJyPDlCTt = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s15 = "boding = cjhdKvLu[2+2+2].split(\"forestall\").join(\"\");" fullword ascii
    $s16 = "var GiuBATNDa = this[boding];" fullword ascii
    $s17 = "staArnBeBap = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s18 = "staArnBeBap = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s19 = "        SVlTqV = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s20 = "        fCmqfB = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x414e and
    8 of them
}