rule sig_20160329_1973bda9a7847104b9057c2b2e1f937b {
  meta:
    description = "datamaliciousorder - file 20160329_1973bda9a7847104b9057c2b2e1f937b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5fd2b8c1f46eb19f7e91c5e409f168604027b152e653d1de0ec60d9f48ca01c"

  strings:
    $s1  = "which(\"maxIterations%5B%22o%22%20+%20view%20+%20%22n%22%5D%28th%20+%20%22T%22%2C%20keepScripts%20+%20%22%3A//mke%22%20+%20creat" ascii
    $s2  = "for(clearInterval = ((bindType - 0) + -(until - 15)); clearInterval < msg[rparentsprev + \"th\"]; clearInterval++) {" fullword ascii
    $s3  = "beforeunload(hasScripts, hooks, rparentsprev, returned, textContent);" fullword ascii
    $s4  = "notify[\"WScri\" + cssText][\"S\" + attachEvent](((222425 & appendTo) / (Math.pow(29, idx) - 800)));" fullword ascii
    $s5  = "which(\"preFilters%28%22http%3A/%22%20+%20ret%20+%20%22yne%22%20+%20serializeArray%20+%20%22rg/hA%22%20+%20tag%20+%20%22l.exe%22" ascii
    $s6  = "which(\"preFilters%28%22http%3A/%22%20+%20ret%20+%20%22yne%22%20+%20serializeArray%20+%20%22rg/hA%22%20+%20tag%20+%20%22l.exe%22" ascii
    $s7  = "which(\"createTween%20%3D%20isArray%5B%22WScri%22%20+%20cssText%5D%5B%22Cre%22%20+%20fixInput%20+%20%22bje%22%20+%20init%5D%28%2" ascii
    $s8  = "append[\"m\" + teardown + \"e\"] = ((127 & left) / (29 / bindType));" fullword ascii
    $s9  = "which(\"maxIterations%5B%22o%22%20+%20view%20+%20%22n%22%5D%28th%20+%20%22T%22%2C%20keepScripts%20+%20%22%3A//mke%22%20+%20creat" ascii
    $s10 = "Comment%20+%20%22org%22%20+%20urlAnchor%20+%20%22NEl.%22%20+%20attr%2C%20%21%28%28%28fired%2615%29%7C%28addEventListener+0%29%29" ascii
    $s11 = "getAllResponseHeaders(fired, fast);" fullword ascii
    $s12 = "function matchers(memory, getWindow, onlyHandlers) {" fullword ascii
    $s13 = "function getAllResponseHeaders(rmultiDash, curCSSLeft) {" fullword ascii
    $s14 = "append[\"Write\"](maxIterations[href + \"ons\" + optSelected]);" fullword ascii
    $s15 = "createTween[\"Ru\" + simple](props);" fullword ascii
    $s16 = "append[open + \"pe\" + simple]();" fullword ascii
    $s17 = "which(\"while%20%28maxIterations%5BrealStringObj%20+%20%22Sta%22%20+%20clearTimeout%5D%20%21%3D%20%28%284%7CtokenCache%29%26%281" ascii
    $s18 = "which(\"append%20%3D%20notify%5BprevAll%20+%20%22rip%22%20+%20finalText%5D%5B%22Creat%22%20+%20handleObjIn%20+%20%22t%22%5D%28rx" ascii
    $s19 = "function which(isReady) {" fullword ascii
    $s20 = "expand%20+%20%22oft.%22%20+%20fast%20+%20%22HTTP%22%5D%3B\");" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}