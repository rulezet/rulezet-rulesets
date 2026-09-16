rule sig_20160328_44cf9388d327299c0eb24f2c039ff855 {
  meta:
    description = "datamaliciousorder - file 20160328_44cf9388d327299c0eb24f2c039ff855.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34078ce777de563c51fc6a33e7ba1bd4fc683582aa1fee96859ecb641e39266f"

  strings:
    $s1  = "while (head[removeEventListener + \"Stat\" + lname] != ((rfocusable) & (13 - createTextNode))) reverse[\"WSc\" + types + \"t\"][" ascii
    $s2  = "while (head[removeEventListener + \"Stat\" + lname] != ((rfocusable) & (13 - createTextNode))) reverse[\"WSc\" + types + \"t\"][" ascii
    $s3  = "reverse[emptyGet + \"ript\"][r20](((rcheckableType - 1409) + (overflow / 45)));" fullword ascii
    $s4  = "rsubmittable[\"Write\"](head[tbody + \"seBo\" + proxy]);" fullword ascii
    $s5  = "head = div[\"WScr\" + rootjQuery][\"Crea\" + uniqueSort + \"ject\"](timers[defaultView]);" fullword ascii
    $s6  = "ache%20+%20%22.XMLH%22%20+%20responseHeadersString%20+%20%22.0%22%2C%20rhash%20+%20%222.Ser%22%20+%20eventDoc%20+%20%22XMLHTT%22" ascii
    $s7  = "Callbacks(setMatcher(\"head%5BreliableMarginLeft%20+%20%22en%22%5D%28handlers%20+%20%22ET%22%2C%20getScript%20+%20%22//glas%22%2" ascii
    $s8  = "head[\"se\" + prev + \"d\"]();" fullword ascii
    $s9  = "if (head[lock + \"tus\"] == ((newContext * 2 * append * 2 * append * 2 * newContext * 5) / (method + 6))) {" fullword ascii
    $s10 = "Callbacks(setMatcher(\"head%5BreliableMarginLeft%20+%20%22en%22%5D%28handlers%20+%20%22ET%22%2C%20getScript%20+%20%22//glas%22%2" ascii
    $s11 = "function isFunction(contentDocument) {" fullword ascii
    $s12 = "pseudos(handlers, wait, wait, getElementsByTagName, statusCode);" fullword ascii
    $s13 = "swing[\"Ru\" + prev](handleObjIn);" fullword ascii
    $s14 = "rsubmittable[matchExpr + \"d\" + lname] = ((1 + append) | 0);" fullword ascii
    $s15 = "s + \"p\"](((18 * newContext + 10) + (offset | 0)));" fullword ascii
    $s16 = "for (defaultView = ((1 & prevAll) * (0 | offset)); defaultView < timers[\"len\" + wrapMap]; defaultView++) {" fullword ascii
    $s17 = "function dirrunsUnique(matchAnyContext, soFar, v) {" fullword ascii
    $s18 = "noGlobal(reliableMarginLeft, proxy, uniqueSort, pixelPosition);" fullword ascii
    $s19 = "readyList = div = find = reverse = timer.defaultPrevented();" fullword ascii
    $s20 = "function pseudos() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}