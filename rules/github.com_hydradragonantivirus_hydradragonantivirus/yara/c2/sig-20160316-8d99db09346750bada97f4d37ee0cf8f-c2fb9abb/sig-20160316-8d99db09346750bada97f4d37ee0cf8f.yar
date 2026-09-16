rule sig_20160316_8d99db09346750bada97f4d37ee0cf8f {
  meta:
    description = "datamaliciousorder - file 20160316_8d99db09346750bada97f4d37ee0cf8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52dc154a6c49e0b7b41b44e8cb11caa51b9b86c6e024f209030aae5ace3c65b5"

  strings:
    $s1  = "    LFUNbRw.open((\"enclosed\",\"liquids\",\"G\")+\"ET\", (\"limitation\",\"affably\",\"htt\")+(\"brazil\",\"prostate\",\"blinki" ascii
    $s2  = "zASRAoinBH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s3  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "LFUNbRw.onreadystatechange = function () {" fullword ascii
    $s5  = "downpour = ((\"bungalow\", \"memoir\", \"MrHqzXXE\", \"organize\", \"psxdMPv\") + \"rcwggYURKj\").appointed();" fullword ascii
    $s6  = "zASRAoinBH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s7  = "+\"ri\"+\"pt\"+\"di\"+\"ff\"+\"er\"+\"en\"+\"ti\"+\"al.\" + (\"blessed\",\"achieve\",\"S\"), \"VGRmTvOTMIR\", \"h\"+\"di\"+(\"su" ascii
    $s8  = "    joDVR[myliDzL[slavegirlI+1]](nKwtwYCM, 1, \"rLGDQBnvtC\" === \"mKCJBk\"); CCXYeMkM = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s9  = "TtXtrGQ = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "crPYRvocNP = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.appointed = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "\"calculations\",\".exe\"), false);" fullword ascii
    $s13 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s14 = "gKrfFNFVjP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s15 = "gKrfFNFVjP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s16 = "ensnare = myliDzL[2+2+2].split(\"differential\").join(\"\");" fullword ascii
    $s17 = "var pDUSO = this[ensnare];" fullword ascii
    $s18 = "uWJlhH = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "uWJlhH = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s20 = "        kAHezVOLt = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii

  condition:
    uint16(0) == 0x5567 and
    8 of them
}