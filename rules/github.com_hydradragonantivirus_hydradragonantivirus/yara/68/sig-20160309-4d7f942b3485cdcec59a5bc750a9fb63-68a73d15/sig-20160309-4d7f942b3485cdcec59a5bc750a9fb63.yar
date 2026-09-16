rule sig_20160309_4d7f942b3485cdcec59a5bc750a9fb63 {
  meta:
    description = "datamaliciousorder - file 20160309_4d7f942b3485cdcec59a5bc750a9fb63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1663396e773e63578eb6813c9b783c630db1a58a291a45e180e66f8de6d5d91e"

  strings:
    $s1  = "rfxtypes[isLocal](elementMatcher, buildParams + animated + matcherIn + DOMParser + i + name + abort + grep + getAllResponseHeade" ascii
    $s2  = "w(rparentsprev, 2) - when) & (0 | rfocusable)) ^ ((38 * rparentsprev + 29), (flatOptions & 124), (host | 13)))) - (Math.pow(((Ma" ascii
    $s3  = "contentDocument[button + addBack + eventDoc](progress, ((147 - dataAndEvents) / (1794 / empty)));" fullword ascii
    $s4  = "th.pow((rparentsprev & 5), (handlerQueue / 28)) - (documentIsHTML - 5)) & ((implicitRelative + 37), (Math.pow(stopped, 2) - wrap" ascii
    $s5  = "testContext[after](progress.token(), (createTextNode / (74 - conditionFn)), ((8 ^ createTextNode) - (2 * rparentsprev)));" fullword ascii
    $s6  = "), (5 + time))), (((18, time) ^ (1 * createTextNode)) & ((1 & rnamespace) * (0 ^ time)))) - ((Math.pow((129 | matchContext), (18" ascii
    $s7  = "contentDocument = wait[document + camelCase][defaultPrevented + setFilters + fcamelCase + camelCase](thead + toArray + hasClass " ascii
    $s8  = "contentDocument = wait[document + camelCase][defaultPrevented + setFilters + fcamelCase + camelCase](thead + toArray + hasClass " ascii
    $s9  = "contentDocument[checkNonElements + condense]();" fullword ascii
    $s10 = "wait[excess + pixelMarginRightVal][overrideMimeType + docElem](((9583 & send) + (1680 * curOffset + 409)));" fullword ascii
    $s11 = "rfxtypes[isLocal](elementMatcher, buildParams + animated + matcherIn + DOMParser + i + name + abort + grep + getAllResponseHeade" ascii
    $s12 = "wait = ((158 - nextAll), ((3 | (rfocusable * 2 + implicitRelative)), this));" fullword ascii
    $s13 = "cors[seekingTransport + content + camelCase + result + condense] = (0 | createTextNode);" fullword ascii
    $s14 = "progress = to[undelegate + addClass + inspect + createCache + contents + speeds](risSimple + funescape) + JSON + identifier + in" ascii
    $s15 = "progress = to[undelegate + addClass + inspect + createCache + contents + speeds](risSimple + funescape) + JSON + identifier + in" ascii
    $s16 = "attachEvent = \".\", tmp = \"pt\", dataPriv = \"TP\", contents = \"tring\";" fullword ascii
    $s17 = "send = 16335, td = \".X\", createTextNode = 0, thead = \"AD\";" fullword ascii
    $s18 = "contentDocument[disabled](includeWidth);" fullword ascii
    $s19 = "host = 8;" fullword ascii
    $s20 = "content = \"si\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}