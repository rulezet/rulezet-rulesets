rule sig_20160309_996cf7f8d2f3f43493dca3270bb0bd94 {
  meta:
    description = "datamaliciousorder - file 20160309_996cf7f8d2f3f43493dca3270bb0bd94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38e615c96c14fae88b0dd54e3e0c74e4944eb8fc91c3fee04e2952b1fe40cc29"

  strings:
    $x1  = "currentTime[firstChild](charCode + groups, includeWidth + progressContexts + nidselect + whitespace + isBorderBox + rkeyEvent + " ascii
    $s2  = "undelegate = rootjQuery[bySet + url + compile + createPositionalPseudo + css + fns + requestHeaders + fn](keys + inspected) + pa" ascii
    $s3  = "slow[stopPropagation](undelegate.jsonpCallback(), (1 + -ontype), ((153 + runescape), (73 - getById), (Math.pow(75, completed) - " ascii
    $s4  = "slow[stopPropagation](undelegate.jsonpCallback(), (1 + -ontype), ((153 + runescape), (73 - getById), (Math.pow(75, completed) - " ascii
    $s5  = "undelegate = rootjQuery[bySet + url + compile + createPositionalPseudo + css + fns + requestHeaders + fn](keys + inspected) + pa" ascii
    $s6  = "currentTime = func[targets + aup + optSelected][udataOld + transport + slideDown + pageYOffset](maxIterations + p + setMatchers " ascii
    $s7  = "responseContainer = func[targets + rmultiDash + mapped][bp + ownerDocument + pageYOffset](getComputedStyle + docElem + off + unw" ascii
    $s8  = "currentTime = func[targets + aup + optSelected][udataOld + transport + slideDown + pageYOffset](maxIterations + p + setMatchers " ascii
    $s9  = " * (hasOwnProperty | 1) / ((completed | 2) * (inPage + 2))) ^ (((ontype & 1) * (ontype + -1)) & ((bool, 248, dirruns) - (1462 / " ascii
    $s10 = "rootjQuery = toArray[random + computed + handlerQueue + selector + unwrap](rcleanScript + needsContext + scripts + dataPriv);" fullword ascii
    $s11 = "func[Data + optSelected][rquery](((specialEasing * 16 + strAbort) | (13555 - compareDocumentPosition)));" fullword ascii
    $s12 = "prevUntil + method + setMatcher, !(10 == ((((reverse - 30) - (matchers / 50)) / ((ontype + 3) + (completed ^ 1))) * ((inPage * 2" ascii
    $s13 = "mouseHooks[pipe + document]();" fullword ascii
    $s14 = "computed = \"at\", pipe = \"clo\", css = \"S\", dirruns = 35, method = \"g4\";" fullword ascii
    $s15 = "structure[unwrap + JSON + handlerQueue] = ((1 + acceptData) | (14 - rmouseEvent));" fullword ascii
    $s16 = "password = \"seria\", eq = \"eB\", cloneNode = 34, animated = \"ream\", multipleContexts = \"ile\", dataPriv = \"ll\";" fullword ascii
    $s17 = "func = (((1184 | setOffset) / (144 / hasOwnProperty)), ((190, strAbort, 3) * (rfxtypes, 33, completed), this));" fullword ascii
    $s18 = "fixHook = 154, rcleanScript = \"WScri\", bool = 203, realStringObj = 43, fn = \"gs\";" fullword ascii
    $s19 = "attr = \"R\", document = \"se\", actualDisplay = \"send\", getById = 26, access = \"lize\";" fullword ascii
    $s20 = "responseContainer[swing + origName + multipleContexts](undelegate, 2);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}