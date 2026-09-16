rule sig_20160316_114bf786b5fea4efe6d4d06fb1a4ef9a {
  meta:
    description = "datamaliciousorder - file 20160316_114bf786b5fea4efe6d4d06fb1a4ef9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62211ac49b74db433c5b7fdcf040b1dfe4f57b35582f7c0b95a5329144adf3d0"

  strings:
    $s1  = "dMRgSL = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s2  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "McPFd.onreadystatechange = function () {" fullword ascii
    $s4  = "    SSdoGCT[nOJOpDRF[suitsI+1]](mdKNbMURy, 1, \"BaebRaUQHN\" === \"MHkfcf\"); cGdRe = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s5  = "dMRgSL = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s6  = "arSuKGOzn = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s7  = "String.prototype.encourage = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "OXpMkM = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s10 = "qkxKBCTC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s11 = "qkxKBCTC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s12 = "var TgmEg = this[bygone];" fullword ascii
    $s13 = "hearsay = ((\"birth\", \"carnage\", \"tPwwounCNPi\", \"recipe\", \"pJLjDWRolDg\") + \"LMkEvjaOmER\").encourage();" fullword ascii
    $s14 = "UqKltSaqy = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s15 = "UqKltSaqy = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s16 = "        jJXLcubxn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii
    $s17 = "        QXJzoBtSBUl = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s18 = "    McPFd.open(\"G\"+(\"vector\",\"stucco\",\"pursue\",\"boards\",\"ET\"), (\"gordon\",\"finest\",\"holdings\",\"h\")+\"tt\"+\"p" ascii
    $s19 = "        QXJzoBtSBUl = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        EkdlsWRJyG = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii

  condition:
    uint16(0) == 0x4471 and
    8 of them
}