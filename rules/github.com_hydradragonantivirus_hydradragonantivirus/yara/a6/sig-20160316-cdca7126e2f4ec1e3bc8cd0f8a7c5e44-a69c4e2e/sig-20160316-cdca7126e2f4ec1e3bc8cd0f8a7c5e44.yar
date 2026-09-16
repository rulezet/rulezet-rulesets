rule sig_20160316_cdca7126e2f4ec1e3bc8cd0f8a7c5e44 {
  meta:
    description = "datamaliciousorder - file 20160316_cdca7126e2f4ec1e3bc8cd0f8a7c5e44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a553ea9bb35e54f225f81b9309d4da21bd3772eb661d4813e18a7ad1829e5434"

  strings:
    $s1  = "vcBFzgiT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s2  = "udo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "cpOrHDESX.onreadystatechange = function () {" fullword ascii
    $s4  = "var OOedJ = this[straightforward];" fullword ascii
    $s5  = "straightforward = pNQzrKMuF[2+2+2].split(\"conversation\").join(\"\");" fullword ascii
    $s6  = "vexatious = ((\"reputable\", \"penknife\", \"TFxQxcjrfI\", \"churchman\", \"pbNVnfhmdz\") + \"USqHecLRqyB\").pomerania();" fullword ascii
    $s7  = "vcBFzgiT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s8  = "    jLwMFVI[pNQzrKMuF[monetaryI+1]](vnDbN, 1, \"ScxsESjnQR\" === \"SFesKJbMKkH\"); eyaLuf = \" \\\"PSEUDO\\\": function( pseudo," ascii
    $s9  = "String.prototype.pomerania = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "dbWDLXgQrT = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "KodJhkxq = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "    cpOrHDESX.open((\"clone\",\"trestle\",\"G\")+\"ET\", \"http:\"+\"//\"+\"tuning\"+\".c\"+(\"author\",\"relate\",\"om\")+\".m" ascii
    $s13 = " ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case" ascii
    $s14 = "jXugEYs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "jXugEYs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s16 = "var pNQzrKMuF = [\"E\"+(\"pounce\",\"enquiries\",\"lattice\",\"By\")+(\"atlas\",\"distributions\",\"trusted\",\"iD\")+\"AfS\", " ascii
    $s17 = "cRMFiCpw = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s18 = "cRMFiCpw = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "        JqmVFlsOTX = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s20 = "        eHGKEQa = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x4761 and
    8 of them
}