rule sig_20160316_e4c89c1aaa0bff606bd999b65372503b {
  meta:
    description = "datamaliciousorder - file 20160316_e4c89c1aaa0bff606bd999b65372503b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e18559af643536fadfbb80ad6ca2ced257c074ff5771212a8b95cc23d7b4abce"

  strings:
    $s1  = "remOPoK = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s2  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "qRWiYuns.onreadystatechange = function () {" fullword ascii
    $s4  = "remOPoK = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s5  = "inflected = ((\"priority\", \"landward\", \"sVdLnzF\", \"transatlantic\", \"pjomUxzi\") + \"fzYvRVhPE\").orders();" fullword ascii
    $s6  = "    GfnoM[LfpOEKucs[swansI+1]](bDdDrL, 1, \"TcQXIULf\" === \"RtGxgODMUi\"); bndYFI = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s7  = "String.prototype.orders = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "YTfwRw = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "ivDtnvI = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s11 = "FnFIWIsD = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s12 = "FnFIWIsD = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "armhearted\",\"45\")+\"hg.e\"+(\"meager\",\"selfsatisfied\",\"fantasy\",\"puddles\",\"xe\"), false);" fullword ascii
    $s14 = "var fbhFef = this[samples];" fullword ascii
    $s15 = "bqrAfaqV = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s16 = "bqrAfaqV = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s17 = "        hFtjvi = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s18 = "        roFftAypPS = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s19 = " pseudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ pseudo ] |" ascii
    $s20 = "} catch (qbQPqUX) { };" fullword ascii

  condition:
    uint16(0) == 0x5954 and
    8 of them
}