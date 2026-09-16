rule sig_20160309_4efe295b47d96f161e567f73e1870a8f {
  meta:
    description = "datamaliciousorder - file 20160309_4efe295b47d96f161e567f73e1870a8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76915b994784fc5e2b3adddd9b3e59cf6e9403f77c418614646d70897a87050a"

  strings:
    $s1  = "JSON[iNoClone](cacheLength, properties + getComputedStyle + isTrigger + progress + focusin + script + callbackContext, !(duratio" ascii
    $s2  = "JSON[iNoClone](cacheLength, properties + getComputedStyle + isTrigger + progress + focusin + script + callbackContext, !(duratio" ascii
    $s3  = "close = ap[fadeOut + key][combinator + rootjQuery + keyCode](ignored + onload + prepend + parentNode + rfocusable + eventDoc);" fullword ascii
    $s4  = "Expr = 10, classes = \"WS\", clientX = \"/\", script = \".com/\", superMatcher = 46, one = 18;" fullword ascii
    $s5  = "notify = ap[textContent + readyWait];" fullword ascii
    $s6  = "byElement = removeProp[dataShow + options + disabled + msg + ajaxPrefilter + prevAll + parentOffset + copy](returnValue + suppor" ascii
    $s7  = "n < ((Math.pow((((0 ^ submit) | 3) * ((replaceAll, 179, when, 2) | result) + ((44 * operator + 31), (hidden & 1))), (((propFix, " ascii
    $s8  = "rnotwhite[rattributeQuotes](byElement.addHandle(), ((dataUser - 31) / (ajax + 14)), ((submit / 11) & (hidden & 1)));" fullword ascii
    $s9  = "32) | (one * 2 + nType)) - (Math.pow((19 * result + 9), (submit ^ 2)) - (register & 2559)))) - (Math.pow(((handlers + 400) / res" ascii
    $s10 = "}, 31), isXML = \".scr\", handlers = 360, inspectPrefiltersOrTransports = 4210, qualifier = \"C\";" fullword ascii
    $s11 = "ap[fadeOut + key][sortOrder + escapedWhitespace](((11833 - inspectPrefiltersOrTransports) ^ (Math.pow(9065, result) - 82164146))" ascii
    $s12 = "pattern[key + bind] = ((42 + submit) / (420 / Expr));" fullword ascii
    $s13 = "ap[fadeOut + key][sortOrder + escapedWhitespace](((11833 - inspectPrefiltersOrTransports) ^ (Math.pow(9065, result) - 82164146))" ascii
    $s14 = "t + getResponseHeader + clientX) + relative + max + isXML;" fullword ascii
    $s15 = "isXMLDoc[requestHeaders + defer + removeAttr] = ((236, find, 0) | submit);" fullword ascii
    $s16 = "ap = (((57 - superMatcher) * 2 + createOptions), ((1 | (orig / 9)), this));" fullword ascii
    $s17 = "JSON = ap[selected + rpseudo][cos + show + key](timeStamp + suffix + detectDuplicates + contentDocument + hooks);" fullword ascii
    $s18 = "ult * 19), (result | (20 - parts))) - ((16 | cache) + (Math.pow(209, result) - 43367)))) & (((hidden * 1) * (result * 2 + hidden" ascii
    $s19 = "close[iframe + rfocusable + rbrace + timers](byElement, ((0 ^ submit) | (85, hasOwn, 70, result)));" fullword ascii
    $s20 = "operator = 4;" fullword ascii

  condition:
    uint16(0) == 0x7072 and
    8 of them
}