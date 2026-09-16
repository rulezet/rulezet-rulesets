rule sig_20160329_b51774b120551648b8329f09ab3be742 {
  meta:
    description = "datamaliciousorder - file 20160329_b51774b120551648b8329f09ab3be742.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a90182c717a6cf5631374c96afb7c0c724b87e8a8eb0044c2a03eb5b8a6574"

  strings:
    $s1  = "postSelector[\"Save\" + animated + \"le\"](promise, ((1 | bp) * 2));" fullword ascii
    $s2  = "postSelector[\"mo\" + removeClass + \"e\"] = ((66 + global) / (83 - timeoutTimer));" fullword ascii
    $s3  = "genFx(\"while%20%28cssNumber%5B%22readyS%22%20+%20rrun%20+%20%22e%22%5D%20%21%3D%20%28%28bubbleType-14%29*%28rCRLF*2%29%29%29%20" ascii
    $s4  = "speed = jqXHR = stop = matcherOut = originalProperties.getAllResponseHeaders();" fullword ascii
    $s5  = "uid(optall, input, implementation, thead, tr);" fullword ascii
    $s6  = "nodeIndex[\"R\" + fireGlobals + \"n\"](promise);" fullword ascii
    $s7  = "for(matched = ((finalValue * 3), (returnFalse & 71), (view * 6 + optgroup), (146, bp)); matched < eventDoc[\"lengt\" + matcherIn" ascii
    $s8  = "for(matched = ((finalValue * 3), (returnFalse & 71), (view * 6 + optgroup), (146, bp)); matched < eventDoc[\"lengt\" + matcherIn" ascii
    $s9  = "rquery(copy, on, completeDeferred, removeAttr, fixHooks);" fullword ascii
    $s10 = "cssNumber = speed[\"WSc\" + rlocalProtocol][\"Creat\" + firstElementChild + \"t\"](eventDoc[matched]);" fullword ascii
    $s11 = "function rquery(to, compiled, dataPriv) {" fullword ascii
    $s12 = "function inspect() {" fullword ascii
    $s13 = "function globalEventContext() {" fullword ascii
    $s14 = "function dataType() {" fullword ascii
    $s15 = "function isArray() {" fullword ascii
    $s16 = "function close(b) {" fullword ascii
    $s17 = "inspect(doneName);" fullword ascii
    $s18 = "function uid(rmultiDash, matchIndexes) {" fullword ascii
    $s19 = "function propName(pseudos, pointerleave) {" fullword ascii
    $s20 = "cssNumber[implementation + \"n\" + removeClass]();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}