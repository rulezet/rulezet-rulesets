rule sig_20160308_af9d1f3ed641ff4b2b337b6bb584241e {
  meta:
    description = "datamaliciousorder - file 20160308_af9d1f3ed641ff4b2b337b6bb584241e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a14a7a83c8a9d29680c360e706e6116506ce89465550b7b2e062766d964201d"

  strings:
    $x1  = "hasDuplicate[getWindow + width](ajaxTransport, cssExpand + setGlobalEval + _ + base + dequeue + rpseudo, !(((((3 & XMLHttpReques" ascii
    $s2  = "- 10)) / ((trim / 49) * (pseudo * 3) + (overrideMimeType, 179, checkOn))) * ((Math.pow((15 * checkOn + 1), (restoreScript, 2)) -" ascii
    $s3  = "t) ^ (41 - valueParts)) & ((68 - overrideMimeType) - (49 & etag))) * (1 * (((nonce / 14) - (token + 89)), XMLHttpRequest * (2 & " ascii
    $s4  = "createPseudo = serialize[domManip + getScript + propFilter + fast](charCode + collection + rejectWith + rmouseEvent + flag + fla" ascii
    $s5  = "createPseudo = serialize[domManip + getScript + propFilter + fast](charCode + collection + rejectWith + rmouseEvent + flag + fla" ascii
    $s6  = "map = \"EMP\", unbind = \"w\", restoreScript = 93, pdataOld = \"lo\", getWindow = \"o\", dataFilter = 106;" fullword ascii
    $s7  = "createPositionalPseudo = propHooks[preMap + setTimeout][contents + tokens + originalProperties](createTextNode + rnumnonpx + mat" ascii
    $s8  = "createPositionalPseudo = propHooks[preMap + setTimeout][contents + tokens + originalProperties](createTextNode + rnumnonpx + mat" ascii
    $s9  = "hasDuplicate[getWindow + width](ajaxTransport, cssExpand + setGlobalEval + _ + base + dequeue + rpseudo, !(((((3 & XMLHttpReques" ascii
    $s10 = "arr = 5, scriptCharset = \"F\", tokens = (function Object.prototype.index() {" fullword ascii
    $s11 = "check[expanded + rejectWith + parentsUntil] = ((pseudo * 1) + -pseudo);" fullword ascii
    $s12 = "self[opener] = ((wrap / 34) ^ (pseudo + -1));" fullword ascii
    $s13 = "_queueHooks[node](rjsonp.index(), ((7 - then) & (1 & interval)), (0 ^ interval));" fullword ascii
    $s14 = "rjsonp = createPseudo[readyState + find + empty + initialInUnit + cssNormalTransform + rnotwhite](div + map + setMatchers) + doc" ascii
    $s15 = "rjsonp = createPseudo[readyState + find + empty + initialInUnit + cssNormalTransform + rnotwhite](div + map + setMatchers) + doc" ascii
    $s16 = "hasDuplicate = propHooks[preMap + percent + pushStack][mouseleave + file + ajaxExtend + rscriptTypeMasked](merge + sel + nodeInd" ascii
    $s17 = "hasDuplicate = propHooks[preMap + percent + pushStack][mouseleave + file + ajaxExtend + rscriptTypeMasked](merge + sel + nodeInd" ascii
    $s18 = "contents = \"Crea\"," fullword ascii
    $s19 = "chAnyContext + position + parents);" fullword ascii
    $s20 = "propHooks = (((5658 / arg) & (184 ^ dataFilter)), ((74 / valueParts) * (29 - callbackName) * 2 * checkOn, this));" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    1 of ($x*) and 4 of them
}