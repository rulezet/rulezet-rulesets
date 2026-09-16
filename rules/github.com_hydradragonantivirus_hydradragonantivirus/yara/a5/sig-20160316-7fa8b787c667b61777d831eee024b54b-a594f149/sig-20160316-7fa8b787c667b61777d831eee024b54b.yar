rule sig_20160316_7fa8b787c667b61777d831eee024b54b {
  meta:
    description = "datamaliciousorder - file 20160316_7fa8b787c667b61777d831eee024b54b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c9f8853b39e47625893a0b122502beb11a33ba291e83b3a4c6356e5d7115096"

  strings:
    $s1  = "tsjodhp\"+(\"botswana\",\"posts\",\"bread\",\"ur.c\")+\"om/v\"+\"4v\"+\"5g\"+\"45\"+\"hg.e\"+\"xe\", false);" fullword ascii
    $s2  = "CPkWqFTy = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s3  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "JUpexBP.onreadystatechange = function () {" fullword ascii
    $s5  = "    JUpexBP.open((\"volleyball\",\"ladder\",\"G\")+\"ET\", \"htt\"+\"p:\"+\"//\"+\"vika\"+(\"bouncing\",\"influenza\",\"cataclys" ascii
    $s6  = "CPkWqFTy = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "    xkSWTzey[HvsLqgPbo[bestialI+1]](mLuIYSoS, 1, \"EhPscEAtgAu\" === \"qpvbRFSY\"); PqBrxo = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s8  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s9  = "nQqYIDsfnVt = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "XIjGnOKcUM = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.memories = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "xNLSpTSHgVM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s13 = "xNLSpTSHgVM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s14 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s15 = "likelihood = HvsLqgPbo[2+2+2].split(\"constraints\").join(\"\");" fullword ascii
    $s16 = "var uFrKzC = this[likelihood];" fullword ascii
    $s17 = "YqNnhh = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s18 = "YqNnhh = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "        JDAeKFvbg = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii
    $s20 = "        dpWNELMIgc = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x4359 and
    8 of them
}