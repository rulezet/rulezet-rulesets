rule sig_20160309_a8bf769290947d4cfc6e95af3a17337d {
  meta:
    description = "datamaliciousorder - file 20160309_a8bf769290947d4cfc6e95af3a17337d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f68c3f0a234c905cf194d2623c6fcd816f0e0ba192df7dc51b6e076ef6adf40"

  strings:
    $s1  = "manipulationTarget[compareDocumentPosition + padding + nextAll](swing + visibility, div + until + parentWindow + cssNumber + par" ascii
    $s2  = "manipulationTarget[compareDocumentPosition + padding + nextAll](swing + visibility, div + until + parentWindow + cssNumber + par" ascii
    $s3  = "properties = eventHandle[replaceWith + rhash][firstChild + hasCompare + code + matcherFromGroupMatchers + hasCompare](arr + scri" ascii
    $s4  = "match = manipulationTarget[sibling + visible + percent];" fullword ascii
    $s5  = "manipulationTarget = eventHandle[unquoted + cacheURL + adjustCSS + hasCompare][pixelMarginRightVal + boxSizingReliable](has + pr" ascii
    $s6  = "manipulationTarget = eventHandle[unquoted + cacheURL + adjustCSS + hasCompare][pixelMarginRightVal + boxSizingReliable](has + pr" ascii
    $s7  = "itespace / 26) + (access * 0)) * (pos & (76, pos))) ^ (((18 + view) / (43 & responseHeaders)) + -((42 / delegateCount) & 1))))))" ascii
    $s8  = "eventHandle = (((10 & inspected) ^ (173, handleObj, 60)), (((access * 1) * getComputedStyle), this));" fullword ascii
    $s9  = "wrapAll = oldfire[ready + style + find + className + defer + filter + styles](timer + rfocusMorph + matchExpr) + letterSpacing +" ascii
    $s10 = "properties = eventHandle[replaceWith + rhash][firstChild + hasCompare + code + matcherFromGroupMatchers + hasCompare](arr + scri" ascii
    $s11 = " dataTypeOrTransport + concat + active + postMap + b;" fullword ascii
    $s12 = "50 + xhrFields), (3 ^ (fireGlobals - 37)))) == ((((hover - 47) + (access + 0)) & ((preexisting ^ 1) + (camelKey | 0))) & ((((rwh" ascii
    $s13 = "oldfire = clientTop[firstChild + curElem + setter + hasCompare](unquoted + event + namespace + s);" fullword ascii
    $s14 = "ents + parse + identifier + checkDisplay + dataAndEvents, !((((((3 & pos) & (3 ^ preexisting)) & ((46 - replaceChild) | (3 & cam" ascii
    $s15 = "clientLeft[support + transports + pointerenter]();" fullword ascii
    $s16 = "invert[stopOnFalse] = ((Math.pow(classes, 2) - not), (63 & isDefaultPrevented), (1 & access));" fullword ascii
    $s17 = "postMap = (function Object.prototype.handleObjIn() {" fullword ascii
    $s18 = "properties[parentOffset + top](match);" fullword ascii
    $s19 = "properties[abort + nextAll]();" fullword ascii
    $s20 = "ogress + parentsUntil + strAbort);" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}