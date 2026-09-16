rule sig_20160308_044f5cfbeba2318b1f2d8b0384fc989b {
  meta:
    description = "datamaliciousorder - file 20160308_044f5cfbeba2318b1f2d8b0384fc989b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f972a1f69178c4cd596055d594afc5ee89e7a45b1ab77108634bfc36790ae95d"

  strings:
    $s1  = " 18) | (marginRight / 31)) * (getComputedStyle * 2 - (Math.pow(onload, 2) - root)) + (31, (hasFocus / 23), (Math.pow(responses, " ascii
    $s2  = "defaultDisplay[matcherFromGroupMatchers](postFinder + attrs, udataOld + active + rtagName + bulk + dataTypeOrTransport + compile" ascii
    $s3  = "position = fired[originalEvent + xml + sortDetached + valueParts + border + splice](compareDocumentPosition + handleObj + active" ascii
    $s4  = ") / (30 + letter))) ^ ((2 ^ (resolveContexts ^ 6)) + (Math.pow((getComputedStyle + 0), (sibling / 24)) - props))), (((Math.pow((" ascii
    $s5  = "fired = password[cached + input + returnFalse + tokens + ajaxExtend + getResponseHeader](complete + on + multipleContexts + read" ascii
    $s6  = "fired = password[cached + input + returnFalse + tokens + ajaxExtend + getResponseHeader](complete + on + multipleContexts + read" ascii
    $s7  = ") + forward + rscriptType + extra + tuple + onerror;" fullword ascii
    $s8  = "delegateType = context[complete + on + getResponseHeader][elems + protocol + linear + fragment + forward + getResponseHeader](is" ascii
    $s9  = "delegateType = context[complete + on + getResponseHeader][elems + protocol + linear + fragment + forward + getResponseHeader](is" ascii
    $s10 = "2) - getJSON), (31 ^ createPositionalPseudo))) - (((47 + namespaces)), ((4 * ajaxTransport + 3) & (newUnmatched & 30)), ((origin" ascii
    $s11 = "defaultDisplay[matcherFromGroupMatchers](postFinder + attrs, udataOld + active + rtagName + bulk + dataTypeOrTransport + compile" ascii
    $s12 = "root = 28, tokens = \"ateO\", getComputedStyle = 5, matcherFromGroupMatchers = \"open\";" fullword ascii
    $s13 = "context = (((15 & optionSet) + (Math.pow(26, cssExpand) - 632)), (((resolveContexts | 5) ^ (onload + 14)), this));" fullword ascii
    $s14 = "1554 / removeEvent), 2) - (updateFunc * 5 + optionSet)) / ((16 | cssExpand) * (0 | cssExpand) + (1 * checked))) * (((Math.pow(15" ascii
    $s15 = "password = context[andSelf + origCount + errorCallback];" fullword ascii
    $s16 = "context[complete + getById + errorCallback][prefix + simple](((69 ^ responseFields) & 17 * rfocusable));" fullword ascii
    $s17 = "camelKey[nodes + func] = ((380 / node) - (3 | winnow));" fullword ascii
    $s18 = "position = fired[originalEvent + xml + sortDetached + valueParts + border + splice](compareDocumentPosition + handleObj + active" ascii
    $s19 = "rCache + appendChild + selector + funescape, !((Math.pow((((Math.pow((letter - 15), cssExpand) - (3 ^ rfocusable)) & ((170, elem" ascii
    $s20 = "defaultDisplay = context[addClass + errorCallback][cached + matchExpr + el + XMLHttpRequest + holdReady](oMatchesSelector + fn +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}