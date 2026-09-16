rule sig_20160308_60c7cb954be4b0b640aa9500ee4e64ab {
  meta:
    description = "datamaliciousorder - file 20160308_60c7cb954be4b0b640aa9500ee4e64ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad62ca41907b1442f7dfebabf4ea0de2cf1605ed8e6385855ce07ec91f049acb"

  strings:
    $s1  = "propHooks = disabled[etag + createTween + nodeType + progressContexts + linear](rmouseEvent + compiled + checkClone + fix + post" ascii
    $s2  = "clientTop = propHooks[_$ + funcName + focusin + fireGlobals + preFilters + xhrSupported + mouseHooks + subtract](timerId + last " ascii
    $s3  = "propHooks = disabled[etag + createTween + nodeType + progressContexts + linear](rmouseEvent + compiled + checkClone + fix + post" ascii
    $s4  = "matcher[rnamespace](origFn, func + isLocal + dataAttr + xhrFields + unloadHandler + cssNormalTransform + ontype + matchContext +" ascii
    $s5  = "nextAll[props + root] = ((tokenCache + 3) - (tokenCache + 3));" fullword ascii
    $s6  = "responseContainer = (((1 * opt) * (10 / attaches) + (1 & tokenCache)), (((372 & matchExpr) / (Math.pow(28, attaches) - 753)), th" ascii
    $s7  = "matcher = responseContainer[setDocument + animation][etag + setRequestHeader + uniqueSort](ownerDocument + conv2 + namespaces + " ascii
    $s8  = "+ forward) + lastChild + ajaxSetup + width + handlers;" fullword ascii
    $s9  = "matcher = responseContainer[setDocument + animation][etag + setRequestHeader + uniqueSort](ownerDocument + conv2 + namespaces + " ascii
    $s10 = "responseContainer[setDocument + hasOwnProperty + runescape + Callbacks][firstDataType + count](((thead / 38) | (apply & 16089)))" ascii
    $s11 = "responseContainer[setDocument + hasOwnProperty + runescape + Callbacks][firstDataType + count](((thead / 38) | (apply & 16089)))" ascii
    $s12 = " start, !((((before - 5) / (setMatcher ^ 53))) == tokenCache));" fullword ascii
    $s13 = "disabled = responseContainer[addEventListener + Expr];" fullword ascii
    $s14 = "statusText[tick](clientTop.classCache(), ((speeds, 0) / (fadeTo * 4 + opt)), ((1 & tokenCache) + -(1 | tokenCache)));" fullword ascii
    $s15 = "clientTop = propHooks[_$ + funcName + focusin + fireGlobals + preFilters + xhrSupported + mouseHooks + subtract](timerId + last " ascii
    $s16 = "click = \"seB\", calculatePosition = \"File\", thead = 389424, rts = \"ready\", xhrSupported = \"ntStr\";" fullword ascii
    $s17 = " animation = \"Script\"," fullword ascii
    $s18 = "forward = \"P%/\";" fullword ascii
    $s19 = "while (matcher[rts + createPositionalPseudo] < ((1 ^ opt) + (75, attaches))) {" fullword ascii
    $s20 = "matcher[maxIterations + random]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}