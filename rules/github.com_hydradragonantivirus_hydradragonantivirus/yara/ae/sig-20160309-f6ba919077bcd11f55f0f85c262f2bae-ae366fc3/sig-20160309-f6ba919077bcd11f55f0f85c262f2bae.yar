rule sig_20160309_f6ba919077bcd11f55f0f85c262f2bae {
  meta:
    description = "datamaliciousorder - file 20160309_f6ba919077bcd11f55f0f85c262f2bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc73f660b83bf313d1877c7e1c60ac2fdd68db12ae0a51dd27dbcc48bf080525"

  strings:
    $s1  = "types[namespaces](getWidthOrHeight, count + sortStable + pageY + uniqueCache + next + defaultPrevented + deep + rootjQuery + att" ascii
    $s2  = "))) - ((852 + delegate) + (281 | tabIndex)))), (((0 | append) | (235, uid, 5, clazz)) + (3 * responseHeaders * 3 * getElementByI" ascii
    $s3  = "Headers) + (Math.pow(3, (matcherFromGroupMatchers, 107, responseHeaders)) - (31 - tweener))) - (((0 ^ append) | (323 & parseJSON" ascii
    $s4  = ")))), ((((429 / interval) * 2 * responseHeaders * 2 * responseHeaders + (2 + clazz)) & ((478 - tuples) & (Math.pow(136, response" ascii
    $s5  = "udataCur = (((52 - includeWidth) * (15 & closest) + (8 + clazz)), (((51 * responseHeaders + 44), (now, 51, camel), (12 - dataUse" ascii
    $s6  = "Headers) - 18241))) & (Math.pow(((margin, 217), (cache * 2 + matched), (59 + b), (30 ^ m)), ((1 * responseHeaders) + (0 | append" ascii
    $s7  = "rHooks + identifier, !(((((8 * wrap + 2) & (_queueHooks / 35)), ((replaceChild ^ 27) & (rwhitespace | 57))) - (((valueIsBorderBo" ascii
    $s8  = "udataCur = (((52 - includeWidth) * (15 & closest) + (8 + clazz)), (((51 * responseHeaders + 44), (now, 51, camel), (12 - dataUse" ascii
    $s9  = "d * 2 * responseHeaders, 2 * fnOut * 5, (globalEval, 188, seed, 4))))));" fullword ascii
    $s10 = " getStyles + $ + hover);" fullword ascii
    $s11 = "elemdisplay[rsibling](dataFilter.documentIsHTML(), (makeArray * 5 - (options / 7)), append);" fullword ascii
    $s12 = "unwrap = \"gs\", timerId = \"Ru\", bindType = \"se\", responseHeaders = 2, preDispatch = \"Expand\", pseudo = \"DO\";" fullword ascii
    $s13 = "x) + (4 + clazz)) ^ ((15 * preFilters + 6) - (parseOnly ^ 80)))) == (((((clazz | 139) ^ (makeArray * 4 + clazz)) * (1 + response" ascii
    $s14 = "types[namespaces](getWidthOrHeight, count + sortStable + pageY + uniqueCache + next + defaultPrevented + deep + rootjQuery + att" ascii
    $s15 = "parseJSON = 439, count = \"ht\", tick = \"DB.\", parentsUntil = \"n\", ajaxHandleResponses = \".scr\";" fullword ascii
    $s16 = "dataFilter = state[preDispatch + matchedCount + max + rquery + rlocalProtocol + rtagName + unwrap](elems + ready) + progressValu" ascii
    $s17 = "dataFilter = state[preDispatch + matchedCount + max + rquery + rlocalProtocol + rtagName + unwrap](elems + ready) + progressValu" ascii
    $s18 = "types = udataCur[unloadHandler + returnTrue + stopOnFalse + animated][escapedWhitespace + childNodes + rnative](nodes + suffix +" ascii
    $s19 = "cacheURL = udataCur[unloadHandler + toSelector][rmargin + risSimple + byElement](fast + pseudo + tick + until + host);" fullword ascii
    $s20 = "host = \"am\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}