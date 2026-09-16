rule sig_20160316_901c2c7318041abb21d10d909f3bd386 {
  meta:
    description = "datamaliciousorder - file 20160316_901c2c7318041abb21d10d909f3bd386.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c0a61c8037fbc9a2f7c2db72c13cf5b42dc577539b187ed6f1ca02e69f65851"

  strings:
    $s1  = "    cDLto.open(\"G\"+(\"analyze\",\"arrive\",\"ET\"), \"htt\"+(\"credence\",\"anthem\",\"moved\",\"p:\")+\"//\"+\"we\"+(\"indone" ascii
    $s2  = "uOLUFDSbda = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s3  = "s[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "cDLto.onreadystatechange = function () {" fullword ascii
    $s5  = "uOLUFDSbda = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s6  = "    zLMbaCWq[gxqlscbKb[fiftythreeI+1]](jqMNciAD, 1, \"sMHVmjQqkE\" === \"UChQMyCUzku\"); AwIXbm = \" \\\"PSEUDO\\\": function( p" ascii
    $s7  = "t\",\"re.\") + (\"refer\",\"quicksilver\",\"S\"), \"enoASavoJW\", (\"scholar\",\"cocks\",\"h\")+\"closureelclo\"+\"su\"+(\"viola" ascii
    $s8  = "bmyPsvWzEdT = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "idIzeMtRsDU = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "gument ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity i" ascii
    $s11 = "OjQPRTg = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s12 = "OjQPRTg = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "var JXmbdQ = this[postcard];" fullword ascii
    $s14 = "xe\"), false);" fullword ascii
    $s15 = "agreement = ((\"nelly\", \"servitor\", \"DNVsMqA\", \"remarkable\", \"pzRSvwQpxF\") + \"TsLrLvfu\").campfire();" fullword ascii
    $s16 = "String.prototype.campfire = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "ygKWyuJtMWA = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s18 = "ygKWyuJtMWA = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s19 = "        cFBBSQHtVeA = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii
    $s20 = "        RRhzVphUeBO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x4465 and
    8 of them
}