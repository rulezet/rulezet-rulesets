rule sig_20160309_241465156eda20f94efbe61b6f19ec79 {
  meta:
    description = "datamaliciousorder - file 20160309_241465156eda20f94efbe61b6f19ec79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0976a2dfb27af6cda647522e0311ee691a0b5badc9635a0c1a8b2dd181a9961b"

  strings:
    $s1  = "augmentWidthOrHeight[rescape + allTypes](border + jsonpCallback + option, sortInput + whitespace + xhrFields + rbuggyMatches + c" ascii
    $s2  = "* ((innerText, 3)) * (Math.pow((buildParams + 0), (webkitMatchesSelector & 2)) - (isArrayLike - 16)), ((((close) + (1 | webkitMa" ascii
    $s3  = "augmentWidthOrHeight = stateString[matcherFromTokens + onerror + clientTop][compiled + offsetParent + settings](el + hide + rmou" ascii
    $s4  = "augmentWidthOrHeight = stateString[matcherFromTokens + onerror + clientTop][compiled + offsetParent + settings](el + hide + rmou" ascii
    $s5  = "risSimple[getAll](timer.cloneNode(), ((16 | val), (19 + inArray), 0), ((compare, 0) | val));" fullword ascii
    $s6  = "timeoutTimer = stateString[traditional + sourceIndex][namespace + rscriptType + operator + jsonProp + condense](escapedWhitespac" ascii
    $s7  = "tchesSelector)) | (Math.pow(3, (cssNumber, 253, fns)) - (4 + close))) ^ (((44 - always)) & ((126, b, 7, fixInput) - (3 * lang)))" ascii
    $s8  = "ction + 0), (startLength - 104)) + ((close * 2) ^ (close * 0))), (((readyList / 42) / (webkitMatchesSelector + 13)) | ((close | " ascii
    $s9  = "9) | (noop / 22))), (((cssNormalTransform / 3) ^ (close + -1)) * (Math.pow(webkitMatchesSelector, (2 & fns)) - (5 ^ val)) + (2 *" ascii
    $s10 = "timeoutTimer = stateString[traditional + sourceIndex][namespace + rscriptType + operator + jsonProp + condense](escapedWhitespac" ascii
    $s11 = "rattributeQuotes[first + rcleanScript]();" fullword ascii
    $s12 = "timer = _load[nodes + elems + type + PI + progressContexts + reliableMarginRight](responseHeadersString + once) + nodeType + app" ascii
    $s13 = "source = \"save\", clearTimeout = \"e\", src = \"r\", easing = \"Resp\", compiled = \"Create\", rscriptType = \"a\";" fullword ascii
    $s14 = "timer = _load[nodes + elems + type + PI + progressContexts + reliableMarginRight](responseHeadersString + once) + nodeType + app" ascii
    $s15 = "box[base + children] = ((12 & m) - (16 - buildParams));" fullword ascii
    $s16 = "hildNodes + keys + idx + callbackName + src + dataTypeExpression, !(7 < (((((val | 1) * (stop - 37)) * ((selection + 173), (sele" ascii
    $s17 = "triggered = augmentWidthOrHeight[easing + apply + seekingTransport];" fullword ascii
    $s18 = "stateString[matcherFromTokens + xml + initialInUnit][fired + originAnchor](((valHooks, 15032) & rdashAlpha));" fullword ascii
    $s19 = "_load = assert[compiled + offsetParent + settings](matcherFromGroupMatchers + initialInUnit + handleObj + msg);" fullword ascii
    $s20 = "timeoutTimer[source + which + username + clearTimeout](timer, ((1 & close) ^ 3));" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}