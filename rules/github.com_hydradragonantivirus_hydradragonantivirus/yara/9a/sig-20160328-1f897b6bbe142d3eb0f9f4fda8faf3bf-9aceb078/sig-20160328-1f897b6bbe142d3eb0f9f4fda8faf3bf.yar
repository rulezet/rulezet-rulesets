rule sig_20160328_1f897b6bbe142d3eb0f9f4fda8faf3bf {
  meta:
    description = "datamaliciousorder - file 20160328_1f897b6bbe142d3eb0f9f4fda8faf3bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83a5892fd4a3ba71936da4c9249d2e92fec6d12b6e335b85ac61ceca1374ecce"

  strings:
    $s1  = "  while(one[cur + \"State\"] != ((capName, 5) & (script | 0))) bubbleType[timers + \"ipt\"][escaped](((querySelectorAll - 55) | " ascii
    $s2  = "  while(one[cur + \"State\"] != ((capName, 5) & (script | 0))) bubbleType[timers + \"ipt\"][escaped](((querySelectorAll - 55) | " ascii
    $s3  = "  for(get = ((cached & 1) | (classNames + -1)); get < Deferred[\"leng\" + handler]; get++) {" fullword ascii
    $s4  = "getter(rneedsContext, readyState, elem);" fullword ascii
    $s5  = "      one = apply[\"WScrip\" + proxy][\"Creat\" + vendorPropName + \"ect\"](Deferred[get]);" fullword ascii
    $s6  = "  charset(replaceChild(\"success%28username%20+%20%22/mus%22%20+%20funcName%20+%20%22oll%22%20+%20PI%20+%20%22m/8oOp%22%20+%20co" ascii
    $s7  = "  charset(replaceChild(\"success%28username%20+%20%22/mus%22%20+%20funcName%20+%20%22oll%22%20+%20PI%20+%20%22m/8oOp%22%20+%20co" ascii
    $s8  = "function getElementsByTagName() {" fullword ascii
    $s9  = "function getter() {" fullword ascii
    $s10 = "    bubbleType[rquickExpr + \"pt\"][escaped](((Math.pow(matcherFromTokens, 2) - related) & (289009 / trigger)));" fullword ascii
    $s11 = "getElementsByTagName(fixHooks, boxSizingReliable, defer, onload);" fullword ascii
    $s12 = "rsubmitterTypes[flag + \"o\" + cssShow + \"e\"] = ((99 / box) & (102 / until));" fullword ascii
    $s13 = "string = bubbleType = apply = matchContext = hooks.keyHooks();" fullword ascii
    $s14 = "function hash(realStringObj) {" fullword ascii
    $s15 = "function stopOnFalse(sibling, base) {" fullword ascii
    $s16 = "function replaceChild(bySet) {" fullword ascii
    $s17 = "function wrap(rnamespace, resolveValues) {" fullword ascii
    $s18 = "function rsubmittable(offsetWidth, bp) {" fullword ascii
    $s19 = "function rts(checkNonElements, qualifier) {" fullword ascii
    $s20 = "rts(responseFields, rejectWith, until, fireGlobals, trigger);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}