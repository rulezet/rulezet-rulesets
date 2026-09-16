rule sig_20160330_4d53f4a0092a23d94b211d1338631a8e {
  meta:
    description = "datamaliciousorder - file 20160330_4d53f4a0092a23d94b211d1338631a8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afeb4d8db3a86007a5dd94fe6a51dd7766156c1c3944c57a6417feb5c5b343d3"

  strings:
    $s1  = "function originalProperties(password, addEventListener, maxIterations) {" fullword ascii
    $s2  = "manipulationTarget(ajax, blur, rquickExpr, unshift);" fullword ascii
    $s3  = "function manipulationTarget(method, doc) {" fullword ascii
    $s4  = "elem[slow + \"pe\"] = ((getAttributeNode * 1) | (getAttributeNode & 1));" fullword ascii
    $s5  = "function rsibling(password, bySet, webkitMatchesSelector) {" fullword ascii
    $s6  = "        elem[\"SaveT\" + guid](protocol, ((errorCallback - 49) | (getAttributeNode + -1)));" fullword ascii
    $s7  = "    keys(\"stop&5B&22op&22&20+&20makeArray&5D&28&22GE&22&20+&20crossDomain&2C&20&22http&3A/&22&20+&20isArray&20+&20&22nsaci.&22&" ascii
    $s8  = "function msg(responseHeadersString, emptyGet, rattributeQuotes) {" fullword ascii
    $s9  = "pop(siblingCheck, disabled, event, getAttributeNode);" fullword ascii
    $s10 = "cssNormalTransform = context = clone = delay = dir.scrollLeft();" fullword ascii
    $s11 = "    keys(\"context&5Bt&20+&20&22ipt&22&5D&5Bunqueued&5D&28&28&28rheader/13&29*&28getAttributeNode+1&29+&28disconnectedMatch+616&" ascii
    $s12 = "    keys(\"stop&20&3D&20delay&5B&22WScri&22&20+&20pageY&5D&5B&22Cre&22&20+&20resolve&20+&20&22jec&22&20+&20getElementById&5D&28p" ascii
    $s13 = "    keys(\"context&5Bt&20+&20&22ipt&22&5D&5Bunqueued&5D&28&28&28rheader/13&29*&28getAttributeNode+1&29+&28disconnectedMatch+616&" ascii
    $s14 = "function keys(defaultPrefilter) {" fullword ascii
    $s15 = "function stored(configurable, rneedsContext, rdisplayswap) {" fullword ascii
    $s16 = "        ap(speeds, getAttributeNode, ridentifier, tween, preexisting);" fullword ascii
    $s17 = "    if (stop[ontype + \"t\" + transport + \"tus\"] == ((jQuery & 243) | (curValue | 0))) {" fullword ascii
    $s18 = "    keys(\"context&5B&22WSc&22&20+&20blur&20+&20&22t&22&5D&5Bappend&20+&20&22e&22&20+&20siblingCheck&5D&28&28&28Math.pow&28preex" ascii
    $s19 = "    keys(\"context&5B&22WSc&22&20+&20blur&20+&20&22t&22&5D&5Bappend&20+&20&22e&22&20+&20siblingCheck&5D&28&28&28Math.pow&28preex" ascii
    $s20 = "    keys(\"stop&5B&22op&22&20+&20makeArray&5D&28&22GE&22&20+&20crossDomain&2C&20&22http&3A/&22&20+&20isArray&20+&20&22nsaci.&22&" ascii

  condition:
    uint16(0) == 0x6272 and
    8 of them
}