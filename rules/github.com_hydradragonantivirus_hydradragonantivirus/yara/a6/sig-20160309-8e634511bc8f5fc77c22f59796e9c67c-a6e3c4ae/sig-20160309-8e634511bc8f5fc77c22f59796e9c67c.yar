rule sig_20160309_8e634511bc8f5fc77c22f59796e9c67c {
  meta:
    description = "datamaliciousorder - file 20160309_8e634511bc8f5fc77c22f59796e9c67c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77706178381ede11140ea3a0eb8386eb5f1dd64a6282a22eabcb6a45d52c324e"

  strings:
    $s1  = "tr[maxIterations] = ((createComment - 29) * (script - 22));" fullword ascii
    $s2  = "unshift[addCombinator + marginRight + current][fix + not](((rprotocol, 130, getPropertyValue) + (6083 + rnative)));" fullword ascii
    $s3  = "msMatchesSelector[rts](stateVal, createTextNode + preFilters + opts + preMap + iframe + pixelPositionVal + delay + opts + overfl" ascii
    $s4  = "noGlobal[opts + style + valueParts + prevAll](push, (2 & (createComment - 27)));" fullword ascii
    $s5  = "noGlobal = unshift[reliableMarginLeftVal + dequeue][delegateCount + clientLeft + sort](height + hasScripts + timeout);" fullword ascii
    $s6  = "unshift = (((154 + speeds) & (205 + escaped)), ((Math.pow((200 / using), 2) - (hash + 0)), this));" fullword ascii
    $s7  = " * ((((16 - byElement) | (117 - after)) - ((14 & flatOptions) * 3 + (map)))) == 10));" fullword ascii
    $s8  = "msMatchesSelector[rts](stateVal, createTextNode + preFilters + opts + preMap + iframe + pixelPositionVal + delay + opts + overfl" ascii
    $s9  = "msMatchesSelector = unshift[addCombinator + pageYOffset + capName][root + show + stopQueue + last + sort](originAnchor + bool + " ascii
    $s10 = "msMatchesSelector = unshift[addCombinator + pageYOffset + capName][root + show + stopQueue + last + sort](originAnchor + bool + " ascii
    $s11 = "getPropertyValue = 7247, ap = \"pos\", factory = \"%/\", after = 83;" fullword ascii
    $s12 = "blur = unshift[setup + linear];" fullword ascii
    $s13 = "noGlobal[structure + createFxNow + sort + rmsPrefix](raw);" fullword ascii
    $s14 = "owX + container + handlers + soFar + seed + mouseleave + reliableMarginRight, !((((createElement * 1) * size) + (0 / byElement))" ascii
    $s15 = "push = charset[propFilter + result + replaceWith + self + fixHook + pseudo + createFxNow + replaceWith + fadeToggle](pixelMargin" ascii
    $s16 = "raw = msMatchesSelector[module + id + opacity];" fullword ascii
    $s17 = "var root = \"Cr\"," fullword ascii
    $s18 = "charset = blur[slideToggle + reject + nodeValue + copyIsArray + sortStable + seekingTransport](removeAttribute + cached + detect" ascii
    $s19 = "charset = blur[slideToggle + reject + nodeValue + copyIsArray + sortStable + seekingTransport](removeAttribute + cached + detect" ascii
    $s20 = "    script = 23," fullword ascii

  condition:
    uint16(0) == 0x6d72 and
    8 of them
}