rule sig_20160328_b09e7cc297d808d174a0ab956e8c1052 {
  meta:
    description = "datamaliciousorder - file 20160328_b09e7cc297d808d174a0ab956e8c1052.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9295c1df59ae156dcc77593953683fd86c06306eacd85e7ecdadf71b5939245"

  strings:
    $s1  = " while(types[rheader + \"dyS\" + responseType] != ((60 / lastModified) | (2 * container))) wrapInner[\"WScri\" + parsed][\"S\" +" ascii
    $s2  = " if(types[\"s\" + finalValue] == ((addGetHookIf - 92) * (err, 254, container) + (43 & structure))) {" fullword ascii
    $s3  = "  nodes[hasCompare + \"File\"](getAttribute, (container + 0));" fullword ascii
    $s4  = "ulated]((Math.pow((33 + originalOptions), (1 * container)) - (5 * attrHandle * 11 * attrHandle * 3)));" fullword ascii
    $s5  = " for(makeArray = ((17 - leadingRelative) / (40 - initialInUnit)); makeArray < unquoted[completeDeferred + \"ng\" + preventDefaul" ascii
    $s6  = " for(makeArray = ((17 - leadingRelative) / (40 - initialInUnit)); makeArray < unquoted[completeDeferred + \"ng\" + preventDefaul" ascii
    $s7  = "function unqueued(delegateTarget) {" fullword ascii
    $s8  = "  rnumnonpx[parent + \"n\"](getAttribute);" fullword ascii
    $s9  = " while(types[rheader + \"dyS\" + responseType] != ((60 / lastModified) | (2 * container))) wrapInner[\"WScri\" + parsed][\"S\" +" ascii
    $s10 = "function head(root) {" fullword ascii
    $s11 = " return unescape(delegateTarget);" fullword ascii
    $s12 = " startTime(unqueued(\"unquoted%20%3D%20%5BdoScroll%20+%20%22ml2.S%22%20+%20collection%20+%20%22erXMLH%22%20+%20nodeName%20+%20%2" ascii
    $s13 = "  head();" fullword ascii
    $s14 = "nodes[\"m\" + reset + \"e\"] = ((3 | parentNode) & 3);" fullword ascii
    $s15 = "function iframe(mozMatchesSelector) {" fullword ascii
    $s16 = "  realStringObj(defaultDisplay, hasCompare, originalOptions, file);" fullword ascii
    $s17 = "function isReady(pop, reliableMarginLeftVal) {" fullword ascii
    $s18 = "function stopPropagation() {" fullword ascii
    $s19 = "function realStringObj() {" fullword ascii
    $s20 = "ha%262%29*%28attrHandle%265%29*container*5*%28elems*2%29*%28elems*5%29%29%29%3B\"));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}