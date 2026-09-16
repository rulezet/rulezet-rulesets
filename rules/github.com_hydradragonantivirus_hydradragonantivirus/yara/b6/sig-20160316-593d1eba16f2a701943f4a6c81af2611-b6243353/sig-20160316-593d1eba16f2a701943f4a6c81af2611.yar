rule sig_20160316_593d1eba16f2a701943f4a6c81af2611 {
  meta:
    description = "datamaliciousorder - file 20160316_593d1eba16f2a701943f4a6c81af2611.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94c3dfc6c2b3f417750fd200f161e6cad341e193c36f71fc53e0d657750764a7"

  strings:
    $s1  = "    xzIjV.open((\"recipient\",\"voluptuous\",\"youse\",\"solve\",\"G\")+\"ET\", (\"nickel\",\"collector\",\"purge\",\"coupon\"," ascii
    $s2  = "lcpCNseAtC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s3  = "on\",\"/v4v5g45\")+\"hg.exe\", false);" fullword ascii
    $s4  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "xzIjV.onreadystatechange = function () {" fullword ascii
    $s6  = " (\"dialogue\",\"ribbon\",\"create\",\"y\")+\"CQ\"+(\"agrarian\",\"wages\",\"TzTr\")+\"DDY\", (\"amelioration\",\"cinder\",\"Mef" ascii
    $s7  = "lcpCNseAtC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s8  = "    yUyhUOY[MXAPtlk[spuriousI+1]](sOGeHUQQ, 1, \"lEohAx\" === \"CrSTikai\"); yMJbLgFs = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s9  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "eNksaGmTWrG = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.proceeding = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "EntuIhaCRnS = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s13 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s14 = "bceDaubLhtx = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s15 = "bceDaubLhtx = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s16 = "var tEBgkFo = this[sitemap];" fullword ascii
    $s17 = "excavation = ((\"plaid\", \"boating\", \"sSkKIKS\", \"affiliate\", \"pvRPFsUAbwX\") + \"qjTjGnquAX\").proceeding();" fullword ascii
    $s18 = "YqWLkiMRB = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "YqWLkiMRB = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "        LSLDAjOVc = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii

  condition:
    uint16(0) == 0x4e78 and
    8 of them
}