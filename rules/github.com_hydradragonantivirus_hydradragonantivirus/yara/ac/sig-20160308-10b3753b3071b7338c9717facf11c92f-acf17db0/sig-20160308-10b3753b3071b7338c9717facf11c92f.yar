rule sig_20160308_10b3753b3071b7338c9717facf11c92f {
  meta:
    description = "datamaliciousorder - file 20160308_10b3753b3071b7338c9717facf11c92f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8a9af01a3bc30da9dafb1f624b958d360f7cfd715da8d0e8fbd865261124a5"

  strings:
    $s1  = "lastChild = includeWidth[not + emptyStyle + getElementsByClassName][_ + caption + diff + has + maxWidth](password + reverse + fo" ascii
    $s2  = "lastChild = includeWidth[not + emptyStyle + getElementsByClassName][_ + caption + diff + has + maxWidth](password + reverse + fo" ascii
    $s3  = "adown[styles](getPropertyValue.hasFocus(), ((1 | bubbleType) + -1), ((pattern / 30) / (Math.pow(opts, 2) - useCache)));" fullword ascii
    $s4  = "getPropertyValue = nextSibling[option + nonce + complete + selected + click + stateVal + adjusted](qualifier + unbind) + removeC" ascii
    $s5  = "qualifier = \"%TEMP%\"," fullword ascii
    $s6  = "lastChild[createInputPseudo + opt + eventHandle](border, nextAll + index + source + startLength + count + timerId + type + getJS" ascii
    $s7  = "nativeStatusText[firingIndex + extend](lastChild[getElementsByName + tuples + rejectWith + rnumnonpx + j]);" fullword ascii
    $s8  = "lastChild[createInputPseudo + opt + eventHandle](border, nextAll + index + source + startLength + count + timerId + type + getJS" ascii
    $s9  = "nextSibling = requestHeaders[_ + invert + inPage + closest + next](not + first + head + doc);" fullword ascii
    $s10 = "nextAll = \"h\", siblingCheck = \"c\", password = \"M\";" fullword ascii
    $s11 = "getPropertyValue = nextSibling[option + nonce + complete + selected + click + stateVal + adjusted](qualifier + unbind) + removeC" ascii
    $s12 = "nativeStatusText = includeWidth[top + defaultPrefilter + transport][rmouseEvent + bool + pixelMarginRightVal](async + until + pa" ascii
    $s13 = "includeWidth[pnum + cssPrefixes + safeActiveElement + maxWidth][matcherIn + cleanData]((matcherFromTokens - 32) * (opts | 5) * (" ascii
    $s14 = "nativeStatusText = includeWidth[top + defaultPrefilter + transport][rmouseEvent + bool + pixelMarginRightVal](async + until + pa" ascii
    $s15 = "head = \"hel\";" fullword ascii
    $s16 = "var border = \"GET\"," fullword ascii
    $s17 = "lass + parent + rsubmittable + done + siblingCheck + emptyStyle;" fullword ascii
    $s18 = "(27 / one) ^ (1 * (pattern ^ 6)))) == andSelf));" fullword ascii
    $s19 = "ON + reject + isHidden + toggleClass, !(((((0 & pattern) | (0 & pattern)) / ((40 - pixelMarginRight) & (1 * specialEasing))) ^ (" ascii
    $s20 = "transport = \"pt\";" fullword ascii

  condition:
    uint16(0) == 0x7974 and
    8 of them
}