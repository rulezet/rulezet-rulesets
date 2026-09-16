rule sig_20160316_12b6227de6e5181480713cd506ade0b9 {
  meta:
    description = "datamaliciousorder - file 20160316_12b6227de6e5181480713cd506ade0b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e5fc91cbc1233e5a079cc19997d52bea8f81405383d082d3981889be0fb5f4a"

  strings:
    $s1  = "    ppPsVP.open((\"boxes\",\"edition\",\"laden\",\"treadmill\",\"G\")+\"ET\", (\"unhindered\",\"absolution\",\"languor\",\"yeoma" ascii
    $s2  = "\"ceiling\",\"wondering\",\"sh\")+\"ap\"+\"e.de/v4v5g45hg\"+(\"assist\",\"loathsome\",\".exe\"), false);" fullword ascii
    $s3  = "bECMECj = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s4  = "ppPsVP.onreadystatechange = function () {" fullword ascii
    $s5  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "    KRrYj[TLKCdtA[clocksI+1]](mgNuK, 1, \"kSPhWeo\" === \"xoLqhqSycti\"); TrGcirhP = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s7  = "bECMECj = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s8  = "colonization = ((\"implementing\", \"penguin\", \"XvJlIN\", \"bungalow\", \"pbBlzDCVxccY\") + \"iQOALyr\").recipes();" fullword ascii
    $s9  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "aKTCSu = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "BmQmSVQbXJ = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "String.prototype.recipes = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "tPRroRMXb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s14 = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s15 = "tPRroRMXb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s16 = "var YYYck = this[trying];" fullword ascii
    $s17 = "trying = TLKCdtA[2+2+2].split(\"judge\").join(\"\");" fullword ascii
    $s18 = "pXJtKeGHXH = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "pXJtKeGHXH = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s20 = "        wkizrpoN = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii

  condition:
    uint16(0) == 0x794a and
    8 of them
}