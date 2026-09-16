rule sig_20160325_95d8a581417ef9209eb8d0aa9467ae55 {
  meta:
    description = "datamaliciousorder - file 20160325_95d8a581417ef9209eb8d0aa9467ae55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f0bfbd26b8b92884dbc273626173e339af83396f2bb9a3a56683631cde77f61"

  strings:
    $s1  = "matchesSelector[event + \"pe\"] = (2, (hasCompare, 225, l, 231), (Math.pow(postDispatch, 2) - relative), (1 * css));" fullword ascii
    $s2  = "fadeOut[\"WScrip\" + i][\"Slee\" + optgroup](((Math.pow(handlerQueue, 2) - rfocusable) / (690 / head)));" fullword ascii
    $s3  = "eval(lastChild(\"related%28progressValues%20+%20%22ons%22%20+%20ready%20+%20%22y%22%2C%20%28%28315/manipulationTarget%29%7C%282*" ascii
    $s4  = "eval(lastChild(\"related%28progressValues%20+%20%22ons%22%20+%20ready%20+%20%22y%22%2C%20%28%28315/manipulationTarget%29%7C%282*" ascii
    $s5  = "identifier = \"http:\";" fullword ascii
    $s6  = "newContext(body, manipulationTarget, register, wait, pattern);" fullword ascii
    $s7  = "var after = [][\"constr\" + _evalUrl + \"r\"][cleanData + \"typ\" + register][\"s\" + forward + \"t\"][setup]();" fullword ascii
    $s8  = "matcherFromTokens = base[\"Crea\" + getStyles + \"bjec\" + i](\"WScrip\" + callbackContext + \"ll\");" fullword ascii
    $s9  = "dirrunsUnique(forward);" fullword ascii
    $s10 = "unbind = \"%TEMP\";" fullword ascii
    $s11 = "isPropagationStopped = matcherFromTokens[addClass + \"Enviro\" + compile + \"ntSt\" + Callbacks + \"gs\"](unbind + \"%/\") + tim" ascii
    $s12 = "isPropagationStopped = matcherFromTokens[addClass + \"Enviro\" + compile + \"ntSt\" + Callbacks + \"gs\"](unbind + \"%/\") + tim" ascii
    $s13 = "function emptyGet() {" fullword ascii
    $s14 = "function getPropertyValue() {" fullword ascii
    $s15 = "forward = \"or\";" fullword ascii
    $s16 = "getPropertyValue(time, register);" fullword ascii
    $s17 = "getElementById = \"n\", wait = (function prefix() {}, \"m\"), anim = \"r\";" fullword ascii
    $s18 = "eval(lastChild(\"matcher%5B%22Ru%22%20+%20getElementById%5D%28isPropagationStopped%29%3B\"));" fullword ascii
    $s19 = "head = 46;" fullword ascii
    $s20 = "height(elems, hasContent);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}