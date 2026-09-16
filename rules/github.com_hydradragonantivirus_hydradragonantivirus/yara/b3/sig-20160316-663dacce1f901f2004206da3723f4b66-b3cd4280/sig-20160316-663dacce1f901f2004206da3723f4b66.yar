rule sig_20160316_663dacce1f901f2004206da3723f4b66 {
  meta:
    description = "datamaliciousorder - file 20160316_663dacce1f901f2004206da3723f4b66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55e6db1ad1acb42f8bf639182b5c0a9f55cb6d7a9911d80820a833aa7acbae32"

  strings:
    $s1  = "y\",\"reflex\",\"45\")+\"hg\"+\".e\"+(\"downloaded\",\"somalia\",\"macintosh\",\"onerous\",\"xe\"), false);" fullword ascii
    $s2  = "terrace = ((\"concepts\", \"traditionally\", \"hUBEqmWLUI\", \"tempering\", \"pHeqvvP\") + \"pujTWLx\").hypocrite();" fullword ascii
    $s3  = "    CwicMwb.open((\"deformity\",\"wellfounded\",\"fungi\",\"G\")+\"ET\", (\"bubbles\",\"recipient\",\"h\")+\"tt\"+\"p://we\"+\"b" ascii
    $s4  = "LeyaxGH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s5  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "CwicMwb.onreadystatechange = function () {" fullword ascii
    $s7  = "LeyaxGH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s8  = "    cIQelm[plOHuI[destinyI+1]](mcBiAHTbk, 1, \"gyEizHrBBG\" === \"psDXfD\"); puJet = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s9  = "aaDenKKM = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "sDQXvbncTga = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "String.prototype.hypocrite = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s13 = "zkHiMwj = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "zkHiMwj = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "+(\"things\",\"jargon\",\"jKp\"), (\"enhancement\",\"ensue\",\"termination\",\"notebook\",\"E\")+(\"forests\",\"counterpart\",\"" ascii
    $s16 = "VlCjmdTkq = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s17 = "        eDropMKVbC = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s18 = "VlCjmdTkq = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "        cAigYQXNg = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii
    $s20 = " pseudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ pseudo ] |" ascii

  condition:
    uint16(0) == 0x6355 and
    8 of them
}