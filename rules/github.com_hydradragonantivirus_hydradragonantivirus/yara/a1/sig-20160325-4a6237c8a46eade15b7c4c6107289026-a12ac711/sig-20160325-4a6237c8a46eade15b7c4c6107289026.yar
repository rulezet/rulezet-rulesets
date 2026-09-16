rule sig_20160325_4a6237c8a46eade15b7c4c6107289026 {
  meta:
    description = "datamaliciousorder - file 20160325_4a6237c8a46eade15b7c4c6107289026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f9ae245f58b5c02c31a5b9329e7de9e4eace3624a0f4a64fd0889c6c14004e8"

  strings:
    $s1  = "eval(handle(\"setOffset%5B%22o%22%20+%20raw%20+%20%22e%22%20+%20getElementsByTagName%5D%28%22GE%22%20+%20hasContent%2C%20%22htt%" ascii
    $s2  = "eval(handle(\"setOffset%5B%22o%22%20+%20raw%20+%20%22e%22%20+%20getElementsByTagName%5D%28%22GE%22%20+%20hasContent%2C%20%22htt%" ascii
    $s3  = ", simple) * 2 * (setFilters * 5) * (match / 11) * (simple + 0) * (noop - 28));" fullword ascii
    $s4  = "camelCase[\"WScri\" + setMatchers][\"S\" + rlocalProtocol + \"p\"]((222, always, 5) * (simple * 2 + setFilters) * (111, urlAncho" ascii
    $s5  = "preDispatch = \"%TEMP\";" fullword ascii
    $s6  = "function hasScripts() {" fullword ascii
    $s7  = "eval(handle(\"defaultView%28currentTime%2C%20ifModified%2C%20%28%281*setFilters%29+%2848/firingIndex%29%29%2C%20%22saveTo%22%20+" ascii
    $s8  = "td(hasContent, preDispatch, name);" fullword ascii
    $s9  = "ifModified[isHidden + \"p\" + name] = ((firingIndex / 48) | selector);" fullword ascii
    $s10 = "classCache[opacity](((pageXOffset | 8220) - (ofType & 7165)));" fullword ascii
    $s11 = "var response = [][\"const\" + parseHTML + \"tor\"][implicitRelative + \"type\"][dataAttr + \"or\" + startTime][\"apply\"]();" fullword ascii
    $s12 = "currentTime = ajaxSetup[\"Expa\" + sibling + \"iron\" + file + \"rings\"](preDispatch + \"%/\") + keepData + \"gateTy\" + rmulti" ascii
    $s13 = "currentTime = ajaxSetup[\"Expa\" + sibling + \"iron\" + file + \"rings\"](preDispatch + \"%/\") + keepData + \"gateTy\" + rmulti" ascii
    $s14 = "function addToPrefiltersOrTransports() {" fullword ascii
    $s15 = "bup(startTime, slideDown, file, rcomma, keepData);" fullword ascii
    $s16 = "function defaultView(attrHandle, mappedTypes, tokenize, map) {" fullword ascii
    $s17 = "return mappedTypes[map](attrHandle, tokenize);" fullword ascii
    $s18 = "ajaxSetup = classCache[\"Crea\" + rcomma + \"ct\"](remove + \"ipt.S\" + siblings);" fullword ascii
    $s19 = "camelCase[\"WScri\" + setMatchers][\"S\" + rlocalProtocol + \"p\"]((222, always, 5) * (simple * 2 + setFilters) * (111, urlAncho" ascii
    $s20 = "simple = 2;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}