rule sig_20160328_ebbed74bd004f2dfcc11b5bc8f038421 {
  meta:
    description = "datamaliciousorder - file 20160328_ebbed74bd004f2dfcc11b5bc8f038421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec18c6ec2582f88f5de22ce485cb462edbb276e4be15c558db98601309d0c397"

  strings:
    $s1  = "for(deep = 0; deep < getAttribute[rkeyEvent + \"gth\"]; deep++) {" fullword ascii
    $s2  = "delegateTarget(crossDomain(\"after%5BnodeNameSelector%20+%20%22rip%22%20+%20async%5D%5B%22Sl%22%20+%20css%5D%28%28Math.pow%28%28" ascii
    $s3  = "delegateTarget(crossDomain(\"after%5BnodeNameSelector%20+%20%22rip%22%20+%20async%5D%5B%22Sl%22%20+%20css%5D%28%28Math.pow%28%28" ascii
    $s4  = "rId + 2), (delegateType / 7)) - (hasCompare, 243, handle, 9504)));" fullword ascii
    $s5  = "while(callbackContext[stored + \"tate\"] != ((132, pattern, 6) & (uniqueSort * 4))) after[detach + \"ipt\"][sibling]((Math.pow((" ascii
    $s6  = "foot%20+%20%22.exe%22%29%3B\"));" fullword ascii
    $s7  = "rhash[\"Save\" + checked + \"ile\"](tuples, (remove | (192, remove)));" fullword ascii
    $s8  = "function rscriptType(buildFragment, uniqueID) {" fullword ascii
    $s9  = "rhash[\"op\" + truncate]();" fullword ascii
    $s10 = "function col(forward) {" fullword ascii
    $s11 = "callbackContext = blur[rejectWith + \"t\"][len + \"teObje\" + rwhitespace](getAttribute[deep]);" fullword ascii
    $s12 = "blur[nodeNameSelector + \"ript\"][sibling](((3376 + lang) & (37 * unit)));" fullword ascii
    $s13 = "parseXML[\"Ru\" + animated](tuples);" fullword ascii
    $s14 = "callbackContext[\"s\" + truncate + \"d\"]();" fullword ascii
    $s15 = "while(callbackContext[stored + \"tate\"] != ((132, pattern, 6) & (uniqueSort * 4))) after[detach + \"ipt\"][sibling]((Math.pow((" ascii
    $s16 = "originAnchor(hasCompare, initialInUnit, tick);" fullword ascii
    $s17 = "cssFn(complete, uniqueSort);" fullword ascii
    $s18 = "comma%3B\"));" fullword ascii
    $s19 = "rhash[\"Wri\" + msMatchesSelector](callbackContext[\"resp\" + round + \"Body\"]);" fullword ascii
    $s20 = "function tuple() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}