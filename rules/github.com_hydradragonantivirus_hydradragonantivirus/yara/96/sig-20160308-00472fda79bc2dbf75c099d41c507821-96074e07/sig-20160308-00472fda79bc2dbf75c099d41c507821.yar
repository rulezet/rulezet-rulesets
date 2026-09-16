rule sig_20160308_00472fda79bc2dbf75c099d41c507821 {
  meta:
    description = "datamaliciousorder - file 20160308_00472fda79bc2dbf75c099d41c507821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4350314fbe5315e81c9bd941f08bbfe7329a3e1c08f8494cc152a0f1030117ae"

  strings:
    $s1  = "find[specified + win](doScroll, rparentsprev + rfocusable + buildParams + onreadystatechange + password + stopPropagation + Expr" ascii
    $s2  = "head = rtypenamespace[delegateCount + nextUntil + postMap + processData + getPropertyValue](module + originalSettings + defer + " ascii
    $s3  = "head = rtypenamespace[delegateCount + nextUntil + postMap + processData + getPropertyValue](module + originalSettings + defer + " ascii
    $s4  = "unshift[getter](currentTarget.deepDataAndEvents(), ((siblings ^ 0) ^ (cssExpand & 0)), ((rbuggyMatches - 27), siblings));" fullword ascii
    $s5  = "find[specified + win](doScroll, rparentsprev + rfocusable + buildParams + onreadystatechange + password + stopPropagation + Expr" ascii
    $s6  = "8)), (((fx & 31) ^ (siblings | 33)), (fadeTo * 7 * el * 2 / (bind + 14)))) & ((((once & 5) & (Math.pow(fadeTo, 2) - tween)), ((1" ascii
    $s7  = "while (find[combinator + cssProps + dataShow] < ((Math.pow(114, matcherIn) - 12800), (cssExpand * 4))) {" fullword ascii
    $s8  = "type[content + curLeft + strAbort][siblingCheck + dataTypeExpression](((responseContainer - 7879) + matcherIn * 461 * fadeTo));" fullword ascii
    $s9  = "currentTarget = head[requestHeadersNames + setMatchers + ret + defaultView + tabIndex + callbackName](isXML + clientX + oMatches" ascii
    $s10 = "currentTarget = head[requestHeadersNames + setMatchers + ret + defaultView + tabIndex + callbackName](isXML + clientX + oMatches" ascii
    $s11 = "parents = type[getComputedStyle + relative][checkClone + hasFocus + ifModified + rtagName + nextUntil + trigger](mouseenter + va" ascii
    $s12 = "parents = type[getComputedStyle + relative][checkClone + hasFocus + ifModified + rtagName + nextUntil + trigger](mouseenter + va" ascii
    $s13 = "var password = \"k7\"," fullword ascii
    $s14 = "once = 4, opts = \"nonc\", rparentsprev = \"http\", requestHeadersNames = \"Expa\";" fullword ascii
    $s15 = "5 ^ container) / (12 & Data))) & (5 & (propHooks / 28)) * ((matcherIn ^ 1) & (send - 34)))) > matcherIn));" fullword ascii
    $s16 = "type = (((10141 - self) / (173, container, 23)), (matcherIn * 3 * (siblings ^ 3), this));" fullword ascii
    $s17 = "parents[dir + matches](find[username + eased + allTypes + MAX_NEGATIVE + grep + top]);" fullword ascii
    $s18 = "getter = webkitMatchesSelector;" fullword ascii
    $s19 = "content = \"WS\";" fullword ascii
    $s20 = "unshift = head;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}