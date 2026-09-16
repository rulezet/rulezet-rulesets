rule sig_20160316_298e1858c1d3a369602bc263f45d6975 {
  meta:
    description = "datamaliciousorder - file 20160316_298e1858c1d3a369602bc263f45d6975.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b8c77ea3b36cd8272707c0b242bb775c0daaea97c0fb83a3bad6c47b6666c1c"

  strings:
    $s1  = "    dqDxONV[technologicals + (\"donated\",\"circuits\",\"wheelbarrow\",\"removing\",\"e\") + ((\"portray\", \"verse\", \"wnjvMSE" ascii
    $s2  = "circumstantial = ((\"abstracted\", \"sensed\", \"evWDblHT\", \"archaeological\", \"pDHjktnp\") + \"eYosLBHy\").villages();" fullword ascii
    $s3  = "eQpQnfmied = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s4  = "\"+\"m/\"+(\"mercy\",\"bankruptcy\",\"v4\")+\"v5\"+(\"primeval\",\"though\",\"g45hg.exe\"), false);" fullword ascii
    $s5  = "    dqDxONV.open((\"flagship\",\"powerpoint\",\"G\")+\"ET\", \"h\"+\"tt\"+\"p://\"+\"what\"+(\"logging\",\"found\",\"contraction" ascii
    $s6  = "dqDxONV.onreadystatechange = function () {" fullword ascii
    $s7  = "eQpQnfmied = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s8  = "    vOvejkNmW[JkacLEBkJ[samoaI+1]](mTVPOwfUB, 1, \"UbMpYRgi\" === \"AEAdiu\"); PekWpvoX = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s9  = "EYIMQzD = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s11 = "DxckJFDxQkY = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "String.prototype.villages = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "BwoBALaFhKk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s14 = "BwoBALaFhKk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s15 = "grown = JkacLEBkJ[2+2+2].split(\"afflicts\").join(\"\");" fullword ascii
    $s16 = "var SQBVm = this[grown];" fullword ascii
    $s17 = "VWtuvVl = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "VWtuvVl = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        hbiPvH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s20 = "        xroBVSYfGUe = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x4757 and
    8 of them
}