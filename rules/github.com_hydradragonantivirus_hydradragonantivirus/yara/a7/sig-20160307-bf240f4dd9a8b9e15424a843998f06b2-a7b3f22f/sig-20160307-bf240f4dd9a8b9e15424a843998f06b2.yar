rule sig_20160307_bf240f4dd9a8b9e15424a843998f06b2 {
  meta:
    description = "datamaliciousorder - file 20160307_bf240f4dd9a8b9e15424a843998f06b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61648c98a8ea78186b18be784887e300c2a0aee432a71b806b71f28ea04fe025"

  strings:
    $s1  = "MAX_NEGATIVE[concat](map + clearInterval, getJSON + write + focus + bulk + v + reliableMarginRight + button + key + cssNormalTra" ascii
    $s2  = "247), (keys / 50), (Math.pow(computed, 2) - head), (132 / merge))) & (((1 * active) * (124, progressValues, 235, empty)) * ((312" ascii
    $s3  = "removeChild = second[win + responseContainer + backgroundClip + notify + webkitMatchesSelector + charset + hasContent + relatedT" ascii
    $s4  = "MAX_NEGATIVE = matcherFromGroupMatchers[global + ridentifier + add][seekingTransport + rmargin + eq](hookFn + slow + getElements" ascii
    $s5  = "MAX_NEGATIVE = matcherFromGroupMatchers[global + ridentifier + add][seekingTransport + rmargin + eq](hookFn + slow + getElements" ascii
    $s6  = "3), (empty & 3)) - (rneedsContext + 37)))), (((Math.pow((root, 236, count, 52), (empty + 0)) - (module - 2436)) / ((t | 3) - (na" ascii
    $s7  = "returnFalse = matcherFromGroupMatchers[thead + charset + slideToggle][showHide + preMap + append](current + contentType + curOff" ascii
    $s8  = "returnFalse = matcherFromGroupMatchers[thead + charset + slideToggle][showHide + preMap + append](current + contentType + curOff" ascii
    $s9  = "trim = 13, relatedTarget = \"s\", ridentifier = \"Scri\";" fullword ascii
    $s10 = "arget](easing + arg) + statusText + get + originalEvent + write + readyState + winnow + hasCompare + callbackExpect;" fullword ascii
    $s11 = "siblings = matcherFromGroupMatchers[handleObj + temp + write];" fullword ascii
    $s12 = " / onload) - (Math.pow(4, empty) - 10)))), (((createElement ^ 104) - (cached * 6 + rsubmitterTypes)) * ((55 & computed) - (Math." ascii
    $s13 = " 38)), ((doScroll ^ 106) * (rneedsContext - 27) + (parseFromString, 47)), ((username, 572) / (show + 12)), (Math.pow((cached & 1" ascii
    $s14 = "matcherFromGroupMatchers[camelCase + write][callbackName](((10376 | contentDocument) & (28905 - setPositiveNumber)));" fullword ascii
    $s15 = "second = siblings[unqueued + flatOptions + rsingleTag + append](thead + _data + iNoClone + mozMatchesSelector);" fullword ascii
    $s16 = "removeChild = second[win + responseContainer + backgroundClip + notify + webkitMatchesSelector + charset + hasContent + relatedT" ascii
    $s17 = "MAX_NEGATIVE[concat](map + clearInterval, getJSON + write + focus + bulk + v + reliableMarginRight + button + key + cssNormalTra" ascii
    $s18 = "me - 40))) & ((active) | (7 + booleans))))));" fullword ascii
    $s19 = "pow(46, empty) - 2069)) * ((timeStamp / 30) ^ ((defineProperty - 16) | (booleans | 6))) + (((matchAnyContext + 3595) / (letter /" ascii
    $s20 = "guaranteedUnique[write + stopPropagation] = ((1 * active) * (19 - defineProperty));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}