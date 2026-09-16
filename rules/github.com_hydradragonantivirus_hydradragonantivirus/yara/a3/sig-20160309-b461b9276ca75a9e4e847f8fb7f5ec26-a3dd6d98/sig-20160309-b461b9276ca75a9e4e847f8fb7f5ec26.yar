rule sig_20160309_b461b9276ca75a9e4e847f8fb7f5ec26 {
  meta:
    description = "datamaliciousorder - file 20160309_b461b9276ca75a9e4e847f8fb7f5ec26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15fa5de0fc33202ba27a5ae0e03412271940c0d099772bdbc88a42d548783875"

  strings:
    $s1  = "configurable[pageX + matcherFromTokens](ignored, matchIndexes + optgroup + preMap + insertAfter + high + pageX + keyCode + inArr" ascii
    $s2  = "prepend = select[hasContent + dataUser + prototype][transports + th + clazz + implicitRelative + handleObj + postMap](response +" ascii
    $s3  = "prepend = select[hasContent + dataUser + prototype][transports + th + clazz + implicitRelative + handleObj + postMap](response +" ascii
    $s4  = "flatOptions = elementMatchers[transports + th + resolve + username + postMap](handle + rwhitespace + hookFn + timer);" fullword ascii
    $s5  = "select[handle + iframe][preFilters + rwhitespace]((Math.pow((61, max, 14545), (removeEvent / 37)) - (mappedTypes * 5 + Deferred)" ascii
    $s6  = "select[handle + iframe][preFilters + rwhitespace]((Math.pow((61, max, 14545), (removeEvent / 37)) - (mappedTypes * 5 + Deferred)" ascii
    $s7  = "prepend[dirrunsUnique + pipe](stop);" fullword ascii
    $s8  = "matchAnyContext[rfocusable + cssFn + PI] = ((locked - 43) | (getJSON));" fullword ascii
    $s9  = "configurable[pageX + matcherFromTokens](ignored, matchIndexes + optgroup + preMap + insertAfter + high + pageX + keyCode + inArr" ascii
    $s10 = "stop = configurable[hasFocus + getElementsByTagName + defer];" fullword ascii
    $s11 = "((1 ^ rsubmittable), (1 * documentIsHTML)) - (10 + which)) - (1 * documentIsHTML))) & (((Math.pow((3 * documentIsHTML), (0 | doc" ascii
    $s12 = "select = (((Math.pow(266, documentIsHTML) - 70467) & (wrapInner & 507)), ((i * (38 - origName)), this));" fullword ascii
    $s13 = "configurable = select[context + high + dataUser + prototype][hasOwn + fast + scrollLeft](xhr + globalEventContext + newSelector " ascii
    $s14 = "reliableMarginLeft) + focus + triggered + parts + compareDocumentPosition + dataUser;" fullword ascii
    $s15 = "createHTMLDocument = flatOptions[soFar + unqueued + sibling + dataUser + tuples + defaultValue + valHooks + prevObject](clone + " ascii
    $s16 = "configurable = select[context + high + dataUser + prototype][hasOwn + fast + scrollLeft](xhr + globalEventContext + newSelector " ascii
    $s17 = "etag = fromCharCode + head;" fullword ascii
    $s18 = "heckableType) / (8 | documentIsHTML))), ((1 * (opener - 14)) * ((types ^ 23), (matcherIn + 195), (documentIsHTML & 2)))) - (((fi" ascii
    $s19 = "4 ^ i), (24 * documentIsHTML + 6), (time / 36))) - (((ajaxPrefilter & 12) | (remaining & 4)) + ((documentIsHTML + 5) & (i ^ 7)))" ascii
    $s20 = "clone = \"%TEMP\";" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}