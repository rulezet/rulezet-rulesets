rule sig_20160316_bf6907d0618694ed0cb2a6f491577156 {
  meta:
    description = "datamaliciousorder - file 20160316_bf6907d0618694ed0cb2a6f491577156.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddf511790f53f986b05b5c31c513fd79701db52483ae12cdcd2c3a6a0ad78709"

  strings:
    $s1  = "iqfJFBqA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s2  = "    ErSJAm.open(\"G\"+(\"incubation\",\"consist\",\"trace\",\"ET\"), (\"quail\",\"glassy\",\"htt\")+(\"dominate\",\"lined\",\"pa" ascii
    $s3  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "ErSJAm.onreadystatechange = function () {" fullword ascii
    $s5  = "iqfJFBqA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s6  = "    Xhfqr[KCvFbSn[cerebralI+1]](cVyutURMl, 1, \"vQjXvAoG\" === \"IHxPUiJw\"); VPEOYYFO = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s7  = "intersection = ((\"primacy\", \"linnet\", \"jlRvTXqcCK\", \"contrast\", \"pBanVkJIrA\") + \"ChVoTJjG\").luxembourg();" fullword ascii
    $s8  = "wXbVPBNseB = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "EWFxOUYR = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.luxembourg = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s12 = "TJoBWg = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "TJoBWg = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "exe\", false);" fullword ascii
    $s15 = "extensive = KCvFbSn[2+2+2].split(\"psychiatry\").join(\"\");" fullword ascii
    $s16 = ",\"unformed\",\"introduces\",\"\")+\".\"+\"exe\", (\"handbags\",\"leafy\",\"R\")+\"un\", (\"timothy\",\"contraction\",\"almighty" ascii
    $s17 = "var NDQaDqzz = this[extensive];" fullword ascii
    $s18 = "SinKBQY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "SinKBQY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s20 = "        klPXPCGYaHj = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x4643 and
    8 of them
}