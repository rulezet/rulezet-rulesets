rule sig_20160308_5ceb846fee8e168947df813d82436fbe {
  meta:
    description = "datamaliciousorder - file 20160308_5ceb846fee8e168947df813d82436fbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba118ecfe4eb944b2454267adc719a57d4eda59c2a843074e5904d6cbfd8b25b"

  strings:
    $s1  = "preventDefault[parentsUntil](propHooks, matcherFromGroupMatchers + matcherIn + pixelPositionVal + fadeTo + rwhitespace + scrollL" ascii
    $s2  = "rcomma = filters[each + progress + originAnchor][getText + namespaces + originAnchor](document + manipulationTarget + rts);" fullword ascii
    $s3  = "namespace = headers[send + high + emptyStyle + createPositionalPseudo]($ + guid + inspect + overrideMimeType + sibling);" fullword ascii
    $s4  = "eft + addCombinator + statusCode + splice, !(tuple < (((1 * cssFn) | (Math.pow(((16 | fadeIn), (178 + rbracket), (41 - reliableM" ascii
    $s5  = "fadeTo = \"stt\", lang = 46, getText = \"Creat\", prefilterOrFactory = \".scr\", click = \"XMLHTT\";" fullword ascii
    $s6  = "preventDefault = filters[mapped + originAnchor][_evalUrl + targets + isFunction + originAnchor](easing + concat + click + timeou" ascii
    $s7  = "rcomma[refElements + submit + special + docElem](aup, ((Math.pow(20, cssFn) - 368) / (jsonpCallback & 16)));" fullword ascii
    $s8  = "preventDefault = filters[mapped + originAnchor][_evalUrl + targets + isFunction + originAnchor](easing + concat + click + timeou" ascii
    $s9  = "headers = filters[whitespace + inspect];" fullword ascii
    $s10 = "filters[mapped + originAnchor][rheader + next](((lang & 62) + (rbracket & 54)));" fullword ascii
    $s11 = ", 1)) | ((responseHeaders / 17) - (cssFn & 2))) / ((classes * 2 * cssFn * 2 + (risSimple | 3)), ((responseHeaders + 5) & (Math.p" ascii
    $s12 = "j[curValue](aup.cssNormalTransform(), ((outermost - 20) | risSimple), (0 & (risSimple ^ 0)));" fullword ascii
    $s13 = "rcomma[startLength + swap]();" fullword ascii
    $s14 = "rcomma[Deferred](preventDefault[conv2 + uid + current]);" fullword ascii
    $s15 = "splice = \"ok8jhg\", restoreScript = 153;" fullword ascii
    $s16 = "aup = namespace[getWidthOrHeight + box + parseOnly + fxNow + ifModified + classCache + timer](letterSpacing + queue + delegateTy" ascii
    $s17 = "aup = namespace[getWidthOrHeight + box + parseOnly + fxNow + ifModified + classCache + timer](letterSpacing + queue + delegateTy" ascii
    $s18 = "while (preventDefault[unshift + matchesSelector + swap] < (0 | (risSimple | 4))) {" fullword ascii
    $s19 = "filters = ((11 * (tuple | 9) + isSuccess * 2), (((siblings & 13) & (tuple | 7)), this));" fullword ascii
    $s20 = "filters[extend + hash + originAnchor][firingIndex](((isEmptyObject & 124), resolveContexts * 5, (oMatchesSelector & 238), (locat" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}