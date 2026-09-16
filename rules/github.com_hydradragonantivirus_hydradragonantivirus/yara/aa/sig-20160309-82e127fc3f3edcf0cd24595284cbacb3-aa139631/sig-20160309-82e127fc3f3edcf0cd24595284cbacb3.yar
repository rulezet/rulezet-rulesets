rule sig_20160309_82e127fc3f3edcf0cd24595284cbacb3 {
  meta:
    description = "datamaliciousorder - file 20160309_82e127fc3f3edcf0cd24595284cbacb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24357a40d451d99bd6edc3618e92f9fe2b43832a3cf85d9049cbb8b50cbf9ce3"

  strings:
    $x1  = "promise[childNodes](rcleanScript, then + contentType + completed + progressContexts + mouseleave + needsContext + hasScripts + n" ascii
    $s2  = "promise[childNodes](rcleanScript, then + contentType + completed + progressContexts + mouseleave + needsContext + hasScripts + n" ascii
    $s3  = "find = \"te\", then = \"ht\", rcleanScript = \"GET\", host = \"ope\", pixelMarginRightVal = 5, dataType = 715;" fullword ascii
    $s4  = "preferredDoc = timers[pipe + iframe + show][addGetHookIf + keepData + show](rcombinators + size + flag);" fullword ascii
    $s5  = " rmouseEvent) - 1253) - (getAttributeNode ^ 62))) ^ (((results - 68), (css * 5 + pixelMarginRightVal), (17 - reject)) + (254, sp" ascii
    $s6  = "preferredDoc[host + compile]();" fullword ascii
    $s7  = "beforeunload = promise[sibling + password + udataCur];" fullword ascii
    $s8  = "timers[rquickExpr + show][rcomma](((height * 3 + getElementsByTagName) + (8126 & fadeOut)));" fullword ascii
    $s9  = "3), (documentIsHTML | 4)) * (rmouseEvent * 3 ^ (constructor | 1))) * (((documentIsHTML * (1 & documentIsHTML)) + -((Math.pow(36," ascii
    $s10 = "ewContext + swap + prefilterOrFactory + setDocument + wrapInner, !((((((1838 - dataType) | (Math.pow(563, rmouseEvent) - 315918)" ascii
    $s11 = "_load = refElements[Callbacks + outermost + curPosition + returnTrue + insertBefore + compile + rfxtypes + getAll + raw + fire](" ascii
    $s12 = "rattributeQuotes = timers[pipe + iframe + show];" fullword ascii
    $s13 = "TML) ^ (0 | rmouseEvent)))) * ((((2 * scrollTo) ^ 2 * rmouseEvent * 17 * rmouseEvent), (234, constructor)) ^ (((10 | postMap) ^ " ascii
    $s14 = "after = \"adjus\", offsetHeight = 112, lang = \"ToF\", pipe = \"WSc\", size = \".Str\";" fullword ascii
    $s15 = "_load = refElements[Callbacks + outermost + curPosition + returnTrue + insertBefore + compile + rfxtypes + getAll + raw + fire](" ascii
    $s16 = " password = \"nseB\"," fullword ascii
    $s17 = "opt[handle](_load.relative(), (1 * (origName - 50)), ((documentIsHTML + 0) * (documentIsHTML * 0)));" fullword ascii
    $s18 = "keyHooks + properties) + after + find + responseFields + el;" fullword ascii
    $s19 = "promise = timers[rquickExpr + show][original + jsonp + winnow + rpseudo + strAbort + rrun](firstChild + timeout + success + dele" ascii
    $s20 = "refElements = rattributeQuotes[onreadystatechange + when + interval](rquickExpr + pixelMarginRight + fnOver);" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    1 of ($x*) and 4 of them
}