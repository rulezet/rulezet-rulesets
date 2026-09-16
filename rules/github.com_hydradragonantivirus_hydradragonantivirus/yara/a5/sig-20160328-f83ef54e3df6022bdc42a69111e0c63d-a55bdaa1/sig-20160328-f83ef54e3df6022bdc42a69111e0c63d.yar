rule sig_20160328_f83ef54e3df6022bdc42a69111e0c63d {
  meta:
    description = "datamaliciousorder - file 20160328_f83ef54e3df6022bdc42a69111e0c63d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54c5528430b684a1e52e2ac06cde57f86afa2e09c56771fa0dafe9ade0ff8493"

  strings:
    $s1  = "prevUntil = reset[fail + \"ript\"][mouseenter + \"ateOb\" + getBoundingClientRect](fadeOut[acceptData]);" fullword ascii
    $s2  = "if(prevUntil[bup + \"s\"] == (Math.pow((19 * rparentsprev + 11), (propName)) - (15424 | trim))) {" fullword ascii
    $s3  = "while(prevUntil[\"read\" + visibility + \"ate\"] != ((48 / setTimeout) + 3)) stateVal[clearCloneStyle + \"t\"][select + \"p\"]((" ascii
    $s4  = "actualDisplay[\"R\" + contents](visible);" fullword ascii
    $s5  = "while(prevUntil[\"read\" + visibility + \"ate\"] != ((48 / setTimeout) + 3)) stateVal[clearCloneStyle + \"t\"][select + \"p\"]((" ascii
    $s6  = "newContext[cloneNode + \"p\" + configurable] = (aup + (0 / round));" fullword ascii
    $s7  = "function disableScript(step) {" fullword ascii
    $s8  = "addHandle(disableScript(\"visible%20%3D%20actualDisplay%5B%22Expa%22%20+%20returnTrue%20+%20%22nviron%22%20+%20setOffset%20+%20%" ascii
    $s9  = "addHandle(disableScript(\"visible%20%3D%20actualDisplay%5B%22Expa%22%20+%20returnTrue%20+%20%22nviron%22%20+%20setOffset%20+%20%" ascii
    $s10 = "newContext[indirect + \"p\" + border]();" fullword ascii
    $s11 = "current[preMap + \"pt\"][on](((2258 * propName + 484)));" fullword ascii
    $s12 = "w(reliableMarginRight, 2) - scale) & (260 - rtypenamespace)));" fullword ascii
    $s13 = "function pnum(stopPropagation, hash) {" fullword ascii
    $s14 = "detectDuplicates(show, responseHeaders, option);" fullword ascii
    $s15 = "fragment();" fullword ascii
    $s16 = "function fragment() {" fullword ascii
    $s17 = "function preDispatch() {" fullword ascii
    $s18 = "function filter() {" fullword ascii
    $s19 = "slideDown(border, unloadHandler, visibility);" fullword ascii
    $s20 = "string(show);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}