rule sig_20160308_8e5eea9295ecffeffed74c2223e18614 {
  meta:
    description = "datamaliciousorder - file 20160308_8e5eea9295ecffeffed74c2223e18614.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e20995948ca9fd7e031aa3ceee544bdba429c65fd4a2d0f76987c5d2e441a829"

  strings:
    $s1  = "r20 = originalEvent[createDocumentFragment + keepScripts + currentTarget](parentWindow + stopImmediatePropagation + start);" fullword ascii
    $s2  = "ifModified = r20[expanded + handlerQueue + end + clone + all + getJSON](readyList + init) + leadingRelative + compile + simulate" ascii
    $s3  = "ifModified = r20[expanded + handlerQueue + end + clone + all + getJSON](readyList + init) + leadingRelative + compile + simulate" ascii
    $s4  = "readyList = \"%TEMP%\";" fullword ascii
    $s5  = "stop = responseType[amd + triggerHandler][createDocumentFragment + propName + getWidthOrHeight + currentTarget](scrollLeft + inp" ascii
    $s6  = "stop = responseType[amd + triggerHandler][createDocumentFragment + propName + getWidthOrHeight + currentTarget](scrollLeft + inp" ascii
    $s7  = "iframe[extra](ifModified.prev(), (selectors + -1), ((proxy + 23) - (merge - 85)));" fullword ascii
    $s8  = "responseType[amd + scriptCharset + nid + simulate][prop](((combinator * 4 + easing) | (2599 * fixHooks + 1610)));" fullword ascii
    $s9  = "while(stop[firstChild + conv + timerId + getWidthOrHeight] < ((timers + 0) & fixHooks * 2)) {" fullword ascii
    $s10 = "when[curLeft + rpseudo + safeActiveElement](stop[owner + notifyWith + getJSON + getWidthOrHeight + rdisplayswap]);" fullword ascii
    $s11 = "stop[getJSON + fnOver]();" fullword ascii
    $s12 = "nType[round + Symbol] = ((collection | 0) | (els - 37));" fullword ascii
    $s13 = "ext, !(((((10 * implementation + 4) - (rnamespace, 227, preexisting)) * 2) * ((((rxhtmlTag - 81) - (rnative & 31)) - (fixHooks *" ascii
    $s14 = "responseType = (((213, lastChild, 213, valHooks) / (66 - _)), (((4 * lock) ^ (1 * fixHooks)), this));" fullword ascii
    $s15 = "when = responseType[createPositionalPseudo + hasDuplicate + truncate + simulate][resolveValues + add + msMatchesSelector](nodeTy" ascii
    $s16 = "collection = 0, _ = 52, matcherFromGroupMatchers = \"GE\", keepScripts = \"Obje\";" fullword ascii
    $s17 = " + step + rpseudo;" fullword ascii
    $s18 = " 14) + (collection ^ 4)));" fullword ascii
    $s19 = "stop[size](matcherFromGroupMatchers + rnumnonpx, gotoEnd + cur + funescape + fadeOut + indirect + callbackName + modified + cssT" ascii
    $s20 = "when[undelegate + xhr + hooks](ifModified, ((focus / 8) + (radioValue / 9)));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}