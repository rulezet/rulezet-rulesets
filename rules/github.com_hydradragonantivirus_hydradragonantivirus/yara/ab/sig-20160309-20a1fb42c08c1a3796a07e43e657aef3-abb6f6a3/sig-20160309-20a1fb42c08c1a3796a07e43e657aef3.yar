rule sig_20160309_20a1fb42c08c1a3796a07e43e657aef3 {
  meta:
    description = "datamaliciousorder - file 20160309_20a1fb42c08c1a3796a07e43e657aef3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6f1a5eba43ab6750ba41af241660d252b58ac577e89978bfa8c9b734aba60e7"

  strings:
    $s1  = "event = rdashAlpha[unbind + fadeIn + overrideMimeType + soFar + detach + responseType + now + rheaders](unquoted + expando) + se" ascii
    $s2  = "event = rdashAlpha[unbind + fadeIn + overrideMimeType + soFar + detach + responseType + now + rheaders](unquoted + expando) + se" ascii
    $s3  = "expand = prepend[finalValue + getAttribute + overrideMimeType + flatOptions];" fullword ascii
    $s4  = "prepend = (((Math.pow(53, selectedIndex) - 2741) + (Math.pow(once, 2) - combinator)), (((43 - html) ^ 3 * defaultExtra), this));" ascii
    $s5  = "deepDataAndEvents[slideToggle](currentTime + username, fixHook + rdisplayswap + eq + qsaError + fns + matchedCount + pointerente" ascii
    $s6  = "Dispatch | 2052)) / ((Math.pow(offset, 2) - filter) / 49)) * (((rchecked ^ 4) ^ (htmlPrefilter / 46)) / (Math.pow((close ^ 36), " ascii
    $s7  = "getWidthOrHeight = prepend[prev + parseJSON][defineProperty + xml + ajaxPrefilter](matcherFromGroupMatchers + indirect + fadeTog" ascii
    $s8  = "getWidthOrHeight = prepend[prev + parseJSON][defineProperty + xml + ajaxPrefilter](matcherFromGroupMatchers + indirect + fadeTog" ascii
    $s9  = "rnoContent = deepDataAndEvents[_ + includeWidth + window + newUnmatched + one];" fullword ascii
    $s10 = "getWidthOrHeight[prefilterOrFactory + random]();" fullword ascii
    $s11 = "((reliableMarginLeft & 63) & (fontWeight + 43)) / (parent * (7 & close))) + (((7 / close) + -(41 / safeActiveElement)) | ((1 | d" ascii
    $s12 = "tr[rmsPrefix + rnotwhite] = ((44 - margin) | (1 + -parent));" fullword ascii
    $s13 = "getWidthOrHeight[a + marginDiv + window](event, ((123, onerror) / (242, swing, 242, camel)));" fullword ascii
    $s14 = "unquoted = \"%TEMP\";" fullword ascii
    $s15 = "headers[radio] = (unloadHandler, 83, parent);" fullword ascii
    $s16 = "(parent * 2)) - (properties, 236, returnTrue, 1182))) + (((capName / 33) + groups * 2) / (defaultExtra & 7) * (close & 7))) / ((" ascii
    $s17 = "deepDataAndEvents = prepend[resolveValues + preventDefault + parseJSON][offsetHeight + button + window + minWidth](setMatched + " ascii
    $s18 = "deepDataAndEvents = prepend[resolveValues + preventDefault + parseJSON][offsetHeight + button + window + minWidth](setMatched + " ascii
    $s19 = "nonce + pos + newDefer + mozMatchesSelector);" fullword ascii
    $s20 = "noop = inArray + now;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}