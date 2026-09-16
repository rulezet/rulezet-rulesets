rule sig_20160316_4b8b2525f58829aafea9c3fbfc9f6ba4 {
  meta:
    description = "datamaliciousorder - file 20160316_4b8b2525f58829aafea9c3fbfc9f6ba4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a229914d89191d7fc9da7e55d353e20f7f0ea98887c73ae4f795a1317788a26"

  strings:
    $s1  = "qeiTtTs = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s2  = "warship = ((\"fingers\", \"shaky\", \"lYyIDhW\", \"surveillance\", \"pcFfqvJrPTu\") + \"ybHyUNQ\").coast();" fullword ascii
    $s3  = "    FEJuhWgA[WyGzf[installationI+1]](oXmSGMy, 1, \"ctBPKHyb\" === \"uQirwNE\"); SXBOfXy = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s4  = "qeiTtTs = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s5  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s6  = "MkkawAHgLp = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s7  = "SizCgEAGYE = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s8  = "String.prototype.coast = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "    CaDafy.open((\"corporate\",\"irresolute\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//wh\"+\"at\"+(\"heinous\",\"stipulation\",\"winni" ascii
    $s10 = ",\"skv.co\")+\"m/\"+\"v4\"+\"v5\"+\"g4\"+\"5h\"+(\"transcript\",\"jackass\",\"camping\",\"g.\")+\"exe\", false);" fullword ascii
    $s11 = "HuHEhHzQGwn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s12 = "CaDafy.onreadystatechange = function () {" fullword ascii
    $s13 = "HuHEhHzQGwn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s14 = "var vRwNKWd = this[belongs];" fullword ascii
    $s15 = "pzVaGYf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s16 = "pzVaGYf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s17 = "        tbqSqPJGd = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii
    $s18 = "        UShYGF = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s19 = "} catch (yBnkr) { };" fullword ascii
    $s20 = "        WsbTyRO = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use the s" ascii

  condition:
    uint16(0) == 0x6672 and
    8 of them
}