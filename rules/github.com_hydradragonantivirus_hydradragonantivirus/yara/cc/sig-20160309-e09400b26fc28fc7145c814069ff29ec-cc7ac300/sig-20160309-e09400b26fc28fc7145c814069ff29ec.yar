rule sig_20160309_e09400b26fc28fc7145c814069ff29ec {
  meta:
    description = "datamaliciousorder - file 20160309_e09400b26fc28fc7145c814069ff29ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c9dab01196b26b25223250177a0ffa2ecb8e2158be2544daf5106b8c470fa5a"

  strings:
    $x1  = "reverse[resolveContexts + fx](matchedCount + progress, lname + lang + docElem + buildFragment + round + valueParts + delegateTar" ascii
    $s2  = "InUnit))) ^ (((2 * removeEventListener * 3 * whitespace * 2 * whitespace / (1 ^ checkDisplay)) - (Math.pow(4, token) - 11) * (Ma" ascii
    $s3  = "firstDataType[script + check + rtagName](disable, (token));" fullword ascii
    $s4  = "get, !(a == (((((1134 / s) + (1369 / when)) / ((1394 / parentWindow) ^ 2 * token * 2 * token)) | ((1 * outermost) + (0 ^ initial" ascii
    $s5  = "defineProperty = ((273 & newCache), (((188 & simulate) / (Math.pow(31, token) - 914)), this));" fullword ascii
    $s6  = "stopQueue[tweens + head + callbackContext] = ((1 + initialInUnit) + -1);" fullword ascii
    $s7  = "removeEvent = defineProperty[condense + getWindow];" fullword ascii
    $s8  = "_data = removeEvent[grep + compile + responseHeaders](condense + container + cssPrefixes + cacheURL);" fullword ascii
    $s9  = "firstDataType = defineProperty[location + option][childNodes + context + buildFragment + inArray + dataTypeOrTransport + getWind" ascii
    $s10 = "firstDataType = defineProperty[location + option][childNodes + context + buildFragment + inArray + dataTypeOrTransport + getWind" ascii
    $s11 = "win[responseFields](disable.selection(), initialInUnit, ((188, filter) + -(0 | filter)));" fullword ascii
    $s12 = "script = \"saveTo\";" fullword ascii
    $s13 = "nodeType = \"ra\", progress = \"T\", getWindow = \"t\";" fullword ascii
    $s14 = "reverse = defineProperty[location + option][push + each + fnOut + responseHeaders](last + _ + params);" fullword ascii
    $s15 = "head = \"o\";" fullword ascii
    $s16 = "originAnchor[after + delegateCount + buildFragment] = ((1 | initialInUnit) ^ (0 ^ initialInUnit));" fullword ascii
    $s17 = "ements) + createDocumentFragment + nodeType + detach + acceptData + max;" fullword ascii
    $s18 = "reverse[resolveContexts + fx](matchedCount + progress, lname + lang + docElem + buildFragment + round + valueParts + delegateTar" ascii
    $s19 = "reverse[events + html]();" fullword ascii
    $s20 = "splice = reverse[rsubmittable + rquickExpr + pattern];" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}