rule sig_20160328_a78ceab55df92e60eae34f6d1875e788 {
  meta:
    description = "datamaliciousorder - file 20160328_a78ceab55df92e60eae34f6d1875e788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b00e2ffba351eb3879f5e0810130a4e096992095ed3c7470cd223fb577cd17"

  strings:
    $s1  = "while(elemdisplay[unqueued + \"tat\" + handler] != ((defaultPrevented + 34) - (includeWidth / 39))) iNoClone[\"WScri\" + request" ascii
    $s2  = "while(elemdisplay[unqueued + \"tat\" + handler] != ((defaultPrevented + 34) - (includeWidth / 39))) iNoClone[\"WScri\" + request" ascii
    $s3  = "for(rchecked = ((27 / safeActiveElement) + -1); rchecked < fire[readyState + \"th\"]; rchecked++) {" fullword ascii
    $s4  = "escaped(oldfire(\"file%28%22http%3A%22%20+%20len%20+%20%2250su%22%20+%20whitespace%20+%20%22rde%22%20+%20reliableMarginLeftVal%2" ascii
    $s5  = "ersNames][\"Sle\" + assert](((originalProperties - 109) | (hold * 17 * hold)));" fullword ascii
    $s6  = "attributes[\"Save\" + htmlPrefilter + \"e\"](stopOnFalse, ((22 * hold) - (46 & off)));" fullword ascii
    $s7  = "escaped(oldfire(\"fire%20%3D%20%5BifModified%20+%20%22l2.S%22%20+%20col%20+%20%22XMLHT%22%20+%20timer%20+%20%220%22%2C%20clearTi" ascii
    $s8  = "parentsUntil(w, click, emptyGet, setFilters);" fullword ascii
    $s9  = "reliableMarginRight(postFilter, assert, tr);" fullword ascii
    $s10 = "attributes[document + \"yp\" + handler] = ((36 | implicitRelative) / (22 + fadeOut));" fullword ascii
    $s11 = "isLocal[\"WScr\" + max][\"Sle\" + assert](((7054 & margin) & (8191 & checkOn)));" fullword ascii
    $s12 = "function file() {" fullword ascii
    $s13 = "function prevUntil() {" fullword ascii
    $s14 = "function cssShow(structure) {" fullword ascii
    $s15 = "function reliableMarginRight(ofType, isImmediatePropagationStopped, overwritten) {" fullword ascii
    $s16 = "function before(matchers) {" fullword ascii
    $s17 = "function documentIsHTML() {" fullword ascii
    $s18 = "wrapMap(document, htmlPrefilter, whitespace, tr, filter);" fullword ascii
    $s19 = "function oldfire(th) {" fullword ascii
    $s20 = "before(len, origCount, includeWidth);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}