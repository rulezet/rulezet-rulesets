rule sig_20160316_080b783b6919fa4fa2f7d2739b011d31 {
  meta:
    description = "datamaliciousorder - file 20160316_080b783b6919fa4fa2f7d2739b011d31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "083b874bf6248e6a12ee21a1fab6dc5e61e557e4c901d57f1ef5b357896e0553"

  strings:
    $s1  = "bnGUPCX = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s2  = "tXYcI.onreadystatechange = function () {" fullword ascii
    $s3  = "    UnVMhQg[NeIESEPe[unctuousI+1]](AvKpmBLdL, 1, \"dyFTxWa\" === \"MWzyMFjOzL\"); orjCo = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s4  = "bnGUPCX = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s5  = "qJXVHQDGaK = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s6  = "String.prototype.cowed = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "qzcLuJhklp = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "bYEtyigm = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s9  = "bYEtyigm = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s10 = "    tXYcI.open((\"emmanuel\",\"aboriginal\",\"concepts\",\"emendation\",\"G\")+\"ET\", (\"topsyturvy\",\"greenhouse\",\"h\")+\"t" ascii
    $s11 = ",\"confirmation\",\"//\")+\"vi\"+\"p-\"+\"sh\"+\"ap\"+\"e.\"+\"de/v\"+\"4v\"+\"5g\"+\"45\"+\"hg.e\"+\"xe\", false);" fullword ascii
    $s12 = "th\",\"patrimony\",\"rosary\",\"enquiry\",\"Bi\")+\"eYW\", (\"ejaculation\",\"single\",\"dunbar\",\"seacoast\",\"Exp\")+(\"conse" ascii
    $s13 = "var EELprsSyH = this[alabama];" fullword ascii
    $s14 = "GfFzWPtw = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s15 = "GfFzWPtw = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s16 = "        ORiukFRjYi = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s17 = "        NOVFrK = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s18 = "        aozAHga = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use the s" ascii
    $s19 = "} catch (tLevf) { };" fullword ascii

  condition:
    uint16(0) == 0x7367 and
    8 of them
}