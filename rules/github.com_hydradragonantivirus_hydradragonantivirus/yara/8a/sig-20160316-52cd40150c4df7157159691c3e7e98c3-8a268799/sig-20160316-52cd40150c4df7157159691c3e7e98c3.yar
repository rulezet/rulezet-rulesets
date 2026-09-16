rule sig_20160316_52cd40150c4df7157159691c3e7e98c3 {
  meta:
    description = "datamaliciousorder - file 20160316_52cd40150c4df7157159691c3e7e98c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b6c697ed1e267f8f0ce242459dd2b21b9623fa4e711c16d6e8f342842de9028"

  strings:
    $s1  = "NdzepkQGsMp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s2  = "45\"+(\"wines\",\"victory\",\"hg.exe\"), false);" fullword ascii
    $s3  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "KHrDncrwh.onreadystatechange = function () {" fullword ascii
    $s5  = "    KHrDncrwh.open((\"sleet\",\"thoroughly\",\"atmosphere\",\"G\")+\"ET\", \"http://vital4age.\"+(\"mapped\",\"cooper\",\"loudne" ascii
    $s6  = "NdzepkQGsMp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s7  = "    arSVtL[pBzlICqv[bleedingI+1]](YnxmxeLLY, 1, \"UTdyTcRgWwx\" === \"cQUQaM\"); jjOLMoO = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s8  = "matting = ((\"teller\", \"unimpeachable\", \"TNExXhXreF\", \"businesses\", \"paEGAIMkdtTw\") + \"rftlrni\").divide();" fullword ascii
    $s9  = "VavBbiJFYlw = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "kcIjVFwkjRl = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.divide = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s13 = "gDgUjK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "gDgUjK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "QhUB\", \"BvfuADqy\", \"W\"+\"Sc\"+\"di\"+(\"canary\",\"quicksand\",\"civil\",\"sc\")+\"er\"+\"ningript\"+(\"transcripts\",\"pea" ascii
    $s16 = "var pBzlICqv = [\"O\"+\"VXub\"+\"nX\"+\"LU\"+(\"wired\",\"therapy\",\"lg\"), \"d\"+\"Cw\"+(\"prominent\",\"options\",\"Er\")+\"J" ascii
    $s17 = "formulae = pBzlICqv[2+2+2].split(\"discerning\").join(\"\");" fullword ascii
    $s18 = "var UjOxuG = this[formulae];" fullword ascii
    $s19 = "DiYivbiLN = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "DiYivbiLN = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii

  condition:
    uint16(0) == 0x5466 and
    8 of them
}