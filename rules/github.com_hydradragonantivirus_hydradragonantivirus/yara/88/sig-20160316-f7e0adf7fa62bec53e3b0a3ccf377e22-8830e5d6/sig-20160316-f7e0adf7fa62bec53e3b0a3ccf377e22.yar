rule sig_20160316_f7e0adf7fa62bec53e3b0a3ccf377e22 {
  meta:
    description = "datamaliciousorder - file 20160316_f7e0adf7fa62bec53e3b0a3ccf377e22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f38a4635092f1bb1a6716b32ef79f19fbea31e4a1867a21cec554c7807143f6f"

  strings:
    $s1  = "    WAzJjR.open(\"G\"+(\"ungodly\",\"maintenance\",\"ET\"), (\"eyesight\",\"talking\",\"shame\",\"http://vita\")+\"l4\"+\"ag\"+(" ascii
    $s2  = "ntation\",\"e.eu/v4v\")+\"5g\"+\"45\"+\"hg\"+\".exe\", false);" fullword ascii
    $s3  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "WAzJjR.onreadystatechange = function () {" fullword ascii
    $s5  = "blend = ((\"estimated\", \"optimal\", \"sSfbiOL\", \"modulation\", \"pgYjiOpKsso\") + \"dWOBcMARL\").restrict();" fullword ascii
    $s6  = "    excsOHmcV[Mmate[periodicallyI+1]](KOCCq, 1, \"ztzwYKTep\" === \"DolNSVAPfw\"); JXmmU = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s7  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s8  = "String.prototype.restrict = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "KpJMHakSJ = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "JLVpdgAiaMi = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "CAQYtepT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s12 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s13 = "BvOKChqEWuT = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s14 = "BvOKChqEWuT = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s15 = "CAQYtepT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s16 = "        var HoLVzyP = new sjMvS((\"\"+\"A\"+\"pO\"+(\"prepared\",\"agents\",\"DB.\")+(\"helena\",\"screens\",\"thetis\",\"barome" ascii
    $s17 = "ribbon = Mmate[2+2+2].split(\"holland\").join(\"\");" fullword ascii
    $s18 = "var sjMvS = this[ribbon];" fullword ascii
    $s19 = "vdfJzXxcbyY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s20 = "vdfJzXxcbyY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii

  condition:
    uint16(0) == 0x4162 and
    8 of them
}