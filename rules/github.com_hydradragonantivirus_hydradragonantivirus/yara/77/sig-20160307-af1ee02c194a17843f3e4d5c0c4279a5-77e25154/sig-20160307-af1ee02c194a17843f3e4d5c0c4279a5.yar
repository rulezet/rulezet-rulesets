rule sig_20160307_af1ee02c194a17843f3e4d5c0c4279a5 {
  meta:
    description = "datamaliciousorder - file 20160307_af1ee02c194a17843f3e4d5c0c4279a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1562e1e9df8172f0361bbea979c39144d9c4fe6707e8191f6dc92bd94e7c6b84"

  strings:
    $x1  = "globalEval[sel](getScript, properties + arr + uniqueSort + ridentifier + source + DOMParser + notifyWith, !((((((1 ^ fontWeight)" ascii
    $s2  = "globalEval[sel](getScript, properties + arr + uniqueSort + ridentifier + source + DOMParser + notifyWith, !((((((1 ^ fontWeight)" ascii
    $s3  = "ure))) & ((((9 + complete) - (1 * bulk)) - (19 * bulk * 2 - (Math.pow(timerId, 2) - animation))) & (((1 + fontWeight) + (1 * bul" ascii
    $s4  = " scripts[string + firstDataType + makeArray](delegateType, ((valHooks - 50) | bulk));" fullword ascii
    $s5  = " contentType[statusCode](delegateType.iNoClone(), ((1 + -valueIsBorderBox) & (21 - define)), ((17 | _$), (1 + -valueIsBorderBox)" ascii
    $s6  = " contentType[statusCode](delegateType.iNoClone(), ((1 + -valueIsBorderBox) & (21 - define)), ((17 | _$), (1 + -valueIsBorderBox)" ascii
    $s7  = "nodeIndex = func[completed + triggerHandler + visibility + specified + matcher + matcherFromGroupMatchers](promise + postMap + a" ascii
    $s8  = "nodeIndex = func[completed + triggerHandler + visibility + specified + matcher + matcherFromGroupMatchers](promise + postMap + a" ascii
    $s9  = "source = \"om/7\", promise = \"WScr\", setMatcher = 8, split = \"Creat\", getScript = \"GET\", defaultValue = \"readys\";" fullword ascii
    $s10 = "delegateType = nodeIndex[b + preFilter + code + apply + camelKey + onerror](contents + set + superMatcher + fxNow) + rdashAlpha " ascii
    $s11 = "delegateType = nodeIndex[b + preFilter + code + apply + camelKey + onerror](contents + set + superMatcher + fxNow) + rdashAlpha " ascii
    $s12 = " scripts[view](globalEval[parseHTML + inspected + rdashAlpha + fadeIn]);" fullword ascii
    $s13 = "scripts = matchContext[rmargin + bubbleType + results + matcherFromGroupMatchers][split + lang + throws](clearTimeout + writable" ascii
    $s14 = "scripts = matchContext[rmargin + bubbleType + results + matcherFromGroupMatchers][split + lang + throws](clearTimeout + writable" ascii
    $s15 = " scripts[matcher + root + unique]();" fullword ascii
    $s16 = "while (globalEval[defaultValue + originalEvent + triggerHandler] < ((newUnmatched ^ 61) - curValue * 3 * structure)) {" fullword ascii
    $s17 = "matchContext = (((2616 / nodeNameSelector), (111 + jsonp), (114, matches, 39)), (((ret - 6) | (nextAll, 160, setMatcher)), this)" ascii
    $s18 = "matchContext = (((2616 / nodeNameSelector), (111 + jsonp), (114, matches, 39)), (((ret - 6) | (nextAll, 160, setMatcher)), this)" ascii
    $s19 = " scrollLeft[slow] = (52 - cur);" fullword ascii
    $s20 = "k)) ^ ((1 + -valueIsBorderBox) ^ (1 + -valueIsBorderBox))))) == ((1 + (fontWeight | 0)) + (((unqueued * 6 + splice), 1) + ((font" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}