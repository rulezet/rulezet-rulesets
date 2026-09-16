rule sig_20160316_c48ca20528e217d1c83ea0a86fc1b45a {
  meta:
    description = "datamaliciousorder - file 20160316_c48ca20528e217d1c83ea0a86fc1b45a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33ac48ef60758a0bc74e2c3e74ee6e87f8d58a3bbd8d387aa422f1f1f0f5d824"

  strings:
    $s1  = "QqbQFjScXC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s2  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "wBfjEYWk.onreadystatechange = function () {" fullword ascii
    $s4  = "    iTRqFsyV[goEYp[scurvyI+1]](GRxUrXyu, 1, \"ErSPHXkL\" === \"zCCzVIVPmA\"); ekstt = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s5  = "embryonic = ((\"inclusion\", \"absolute\", \"wIDeKfCC\", \"dilapidated\", \"pVDpgSBHtyfX\") + \"DRCfqGDXBx\").spanking();" fullword ascii
    $s6  = "QqbQFjScXC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s7  = "String.prototype.spanking = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "WdQBiuPN = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "PdaPPXpLO = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s11 = "aSKyCmEp = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s12 = "aSKyCmEp = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "\"bricabrac\",\"bother\",\"wedlock\",\"un\"), \"Act\"+\"squalidi\"+\"vs\"+(\"transvaal\",\"democrat\",\"regent\",\"qual\")+\"ide" ascii
    $s14 = "testing = goEYp[2+2+2].split(\"squalid\").join(\"\");" fullword ascii
    $s15 = "var HYBrSNQCP = this[testing];" fullword ascii
    $s16 = "        GpasSpL = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use the s" ascii
    $s17 = "oAmFsVWeJPF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s18 = "oAmFsVWeJPF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s19 = "        QOArEPpQ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii
    $s20 = "    wBfjEYWk.open(\"G\"+(\"blowjobs\",\"drives\",\"ET\"), \"h\"+\"tt\"+\"p:\"+\"//\"+(\"seasoning\",\"throb\",\"appliance\",\"re" ascii

  condition:
    uint16(0) == 0x5251 and
    8 of them
}