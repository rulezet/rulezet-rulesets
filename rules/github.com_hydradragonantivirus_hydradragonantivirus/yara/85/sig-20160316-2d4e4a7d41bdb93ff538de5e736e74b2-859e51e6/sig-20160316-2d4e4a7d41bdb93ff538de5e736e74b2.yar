rule sig_20160316_2d4e4a7d41bdb93ff538de5e736e74b2 {
  meta:
    description = "datamaliciousorder - file 20160316_2d4e4a7d41bdb93ff538de5e736e74b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "184e9ea2cb61e8679ea2da5059dcd5ad58a828296afc70d2bc1139ecd45be85d"

  strings:
    $s1  = "dqTJAeHQnTT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s2  = "njflvzBzx.onreadystatechange = function () {" fullword ascii
    $s3  = " Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "+\"chselkur\"+(\"froze\",\"heading\",\".de/v4v5\")+\"g45hg.\"+\"exe\", false);" fullword ascii
    $s5  = "woeful = ((\"detection\", \"pewter\", \"rDRkolVAOqn\", \"yearly\", \"pLvdzkf\") + \"eWKnIaSlq\").requiem();" fullword ascii
    $s6  = "dqTJAeHQnTT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s7  = "    hTiyzBl[LtFXbp[maltaI+1]](hOsyVmrl, 1, \"Aewokf\" === \"yskdqoXdnsA\"); VVbOj = \" \\\"PSEUDO\\\": function( pseudo, argumen" ascii
    $s8  = "LXlwOzBEPyo = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "jGSvDnBx = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.requiem = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "    njflvzBzx.open((\"neapolitan\",\"compressed\",\"signed\",\"G\")+\"ET\", \"htt\"+(\"hotels\",\"consumers\",\"insecure\",\"thi" ascii
    $s12 = "XjrDBz = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "udo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom " ascii
    $s14 = "XjrDBz = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "        YiRcMqukmI = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use th" ascii
    $s16 = "genie = LtFXbp[2+2+2].split(\"update\").join(\"\");" fullword ascii
    $s17 = "var yiLpXo = this[genie];" fullword ascii
    $s18 = "mNBySsGI = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "mNBySsGI = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s20 = "        vaizCKGSu = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii

  condition:
    uint16(0) == 0x4a71 and
    8 of them
}