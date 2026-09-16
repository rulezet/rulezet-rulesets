rule sig_20160316_f1e5436039527c6c099769daa401a5e6 {
  meta:
    description = "datamaliciousorder - file 20160316_f1e5436039527c6c099769daa401a5e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060d56f19a2d7c5e1d888ebabd44d8777d2cf52b8afe256bd9bc31db2d83c5b6"

  strings:
    $s1  = ")+\"com/v4\"+(\"horrible\",\"shrewdness\",\"v5g45hg.exe\"), false);" fullword ascii
    $s2  = "    zWOdyaJQH.open((\"julie\",\"sword\",\"drinker\",\"G\")+\"ET\", \"htt\"+\"p://vartas\"+(\"brogue\",\"cookbook\",\"syllogism\"" ascii
    $s3  = "    iOWCONBf[eqVSXgrMp[migrantI+1]](stqNkrqq, 1, \"plRxBFKuCxG\" === \"aVQOTaGhw\"); ImykO = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s4  = "PqMbRqkRErW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s5  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "zWOdyaJQH.onreadystatechange = function () {" fullword ascii
    $s7  = "PqMbRqkRErW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "froze = ((\"tours\", \"groove\", \"jmvqDpPELAI\", \"extraction\", \"ppETtcjDloX\") + \"lEvrqGm\").intermediate();" fullword ascii
    $s9  = "String.prototype.intermediate = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "bldogkYEzw = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "eaiyFu = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s13 = "myMrrtopDm = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "myMrrtopDm = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s15 = "    iOWCONBf[eqVSXgrMp[migrantI+1]](stqNkrqq, 1, \"plRxBFKuCxG\" === \"aVQOTaGhw\"); ImykO = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s16 = "\")+\"ur\"+\"erje\"+\"la\"+\"bo\"+\"urerct\", \"whjGExxUQx\", \"OlrqoFvFm\", \"W\"+\"Sc\"+\"la\"+\"bo\"+\"ur\"+\"er\"+\"ri\"+\"p" ascii
    $s17 = "var GskuYCtJL = this[developments];" fullword ascii
    $s18 = "UsYfhGMKE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "UsYfhGMKE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "        kBUPEuLhx = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii

  condition:
    uint16(0) == 0x7a67 and
    8 of them
}