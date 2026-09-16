rule sig_20160328_a5b0457cb94388fd682db9c9649b28c2 {
  meta:
    description = "datamaliciousorder - file 20160328_a5b0457cb94388fd682db9c9649b28c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a8297c900070d3d2180397d65d3dc2931a786be3b28ee152a107c8e0d1919d"

  strings:
    $s1  = "    if (relatedTarget[\"st\" + splice + \"us\"] == ((notifyWith, 82, beforeSend, 59) * (argument - 19) + (curTop / 29))) {" fullword ascii
    $s2  = "    while (relatedTarget[rnamespace + \"Sta\" + lname] != ((serialize) & (29 - testContext))) mouseHooks[\"WScrip\" + defaultExt" ascii
    $s3  = "        hasFocus[second](relatedTarget[\"resp\" + tokenCache + \"Bod\" + iframe]);" fullword ascii
    $s4  = "    while (relatedTarget[rnamespace + \"Sta\" + lname] != ((serialize) & (29 - testContext))) mouseHooks[\"WScrip\" + defaultExt" ascii
    $s5  = "function getPropertyValue(split, returned) {" fullword ascii
    $s6  = "function time(getResponseHeader) {" fullword ascii
    $s7  = "function startTime(emptyGet) {" fullword ascii
    $s8  = "function getAttribute() {" fullword ascii
    $s9  = "function rootjQuery(attributes) {" fullword ascii
    $s10 = "function handlerQueue() {" fullword ascii
    $s11 = "function rsubmittable(async) {" fullword ascii
    $s12 = "source(reset, augmentWidthOrHeight);" fullword ascii
    $s13 = "\"Sle\" + iNoClone](((25, fcamelCase, 185, timeoutTimer) / (21 * animated + 4)));" fullword ascii
    $s14 = "function stored(udataOld) {" fullword ascii
    $s15 = "function source(copyIsArray) {" fullword ascii
    $s16 = "module(expanded, tokenCache, col, contextBackup, rmargin);" fullword ascii
    $s17 = "function module(e, camel) {" fullword ascii
    $s18 = "startTime(originalEvent, hover, scale);" fullword ascii
    $s19 = "        } catch (thead) {}" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}