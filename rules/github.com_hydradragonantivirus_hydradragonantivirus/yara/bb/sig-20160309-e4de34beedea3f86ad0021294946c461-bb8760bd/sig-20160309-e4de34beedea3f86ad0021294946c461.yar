rule sig_20160309_e4de34beedea3f86ad0021294946c461 {
  meta:
    description = "datamaliciousorder - file 20160309_e4de34beedea3f86ad0021294946c461.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9feac32fa394a08552add607ca78b548455beac53c507c888ac35e21a30fd073"

  strings:
    $x1  = "msg = rhtml[attrs + charCode + emptyStyle][currentTarget + locked](processData + trim + newSelector + JSON + onerror + invert);" fullword ascii
    $s2  = "msg[getElementsByTagName](seekingTransport + fadeToggle, preFilters + iNoClone + rjsonp + createPseudo + rbuggyMatches + matcher" ascii
    $s3  = "msg[getElementsByTagName](seekingTransport + fadeToggle, preFilters + iNoClone + rjsonp + createPseudo + rbuggyMatches + matcher" ascii
    $s4  = "crossDomain[onlyHandlers + run + destElements + origName](lname, ((41 ^ split) - (765 / serializeArray)));" fullword ascii
    $s5  = "rhtml[guid + ajax][identifier + stopQueue + elementMatcher](((16608 | currentValue) - 3 * addHandle * 2 * addHandle * 3 * lastMo" ascii
    $s6  = "splice[addCombinator](lname.matched(), (firing / 46), ((_jQuery + -1) / (undelegate)));" fullword ascii
    $s7  = "rhtml[guid + ajax][identifier + stopQueue + elementMatcher](((16608 | currentValue) - 3 * addHandle * 2 * addHandle * 3 * lastMo" ascii
    $s8  = "crossDomain = rhtml[success + ridentifier][throws + submit + cssFn + b + once](n + traditional + rnative + version);" fullword ascii
    $s9  = "acceptData[parts + empty + getPropertyValue + _evalUrl] = ((stop & 67), (rtypenamespace | 52), (duration + 67), firing);" fullword ascii
    $s10 = " + curCSS + delegateCount + get + rattributeQuotes + hasDuplicate + find + reset, !((((_jQuery * 0) | (((adown | 45) - (fixInput" ascii
    $s11 = "swing = _[removeEventListener + setOffset + sortOrder](attrs + buildFragment + parts + nextSibling + clearQueue + stopQueue + st" ascii
    $s12 = "swing = _[removeEventListener + setOffset + sortOrder](attrs + buildFragment + parts + nextSibling + clearQueue + stopQueue + st" ascii
    $s13 = "rnoInnerhtml[combinator] = (1 * (_jQuery | 0));" fullword ascii
    $s14 = "getElementsByTagName = \"open\", locked = \"Object\", destElements = \"Fi\", lastModified = 3, rattributeQuotes = \"/76\", setOf" ascii
    $s15 = "getPropertyValue = \"sitio\", cloneCopyEvent = 41, newSelector = \"X\", stopImmediatePropagation = \"clos\", buildFragment = \"c" ascii
    $s16 = "getElementsByTagName = \"open\", locked = \"Object\", destElements = \"Fi\", lastModified = 3, rattributeQuotes = \"/76\", setOf" ascii
    $s17 = " ((198 & self) + (2 | conv2)), (2 ^ (_jQuery * 0))))) == pixelMarginRightVal));" fullword ascii
    $s18 = "msFullscreenElement[stopImmediatePropagation + submit]();" fullword ascii
    $s19 = "uniqueSort = \"tStrin\", throws = \"Cr\", combinator = \"type\";" fullword ascii
    $s20 = "var version = \"m\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}