rule sig_20160309_5bd2853164a50806c3440c488f9a196f {
  meta:
    description = "datamaliciousorder - file 20160309_5bd2853164a50806c3440c488f9a196f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69ee94fa2f86e80e3133b46ac377beddb80b3deaba4bf191b98cc64e46ed9616"

  strings:
    $s1  = "hash[Deferred](_queueHooks, valHooks + slow + swing + boolHook + qsaError + stopQueue + valueParts + setter + responseHeadersStr" ascii
    $s2  = "hash = open[inspectPrefiltersOrTransports + username][unquoted + safeActiveElement + readyWait + username](emptyGet + minWidth +" ascii
    $s3  = "hash = open[inspectPrefiltersOrTransports + username][unquoted + safeActiveElement + readyWait + username](emptyGet + minWidth +" ascii
    $s4  = "hash[Deferred](_queueHooks, valHooks + slow + swing + boolHook + qsaError + stopQueue + valueParts + setter + responseHeadersStr" ascii
    $s5  = "originalProperties[reliableMarginLeftVal](postSelector.style(), ((nativeStatusText * 0) / (implementation & 29)), (onerror & 1))" ascii
    $s6  = "tabIndex[fixHook + ignored](postSelector, (matcherFromGroupMatchers & (60 / implementation)));" fullword ascii
    $s7  = "contentDocument = open[add + ajaxHandleResponses + combinator];" fullword ascii
    $s8  = "overwritten = contentDocument[fadeTo + random + self](add + ajaxHandleResponses + combinator + ownerDocument + option);" fullword ascii
    $s9  = "postSelector = overwritten[rtagName + trim + noConflict + isArrayLike + close + curOffset + cssShow](responses + fast + assert) " ascii
    $s10 = "originalProperties[reliableMarginLeftVal](postSelector.style(), ((nativeStatusText * 0) / (implementation & 29)), (onerror & 1))" ascii
    $s11 = "relative[optSelected + boxSizingReliable + binary] = ((rclickable, 1) + -(nativeStatusText + 0));" fullword ascii
    $s12 = "origType[support] = ((origName - 22) | (nativeStatusText ^ 0));" fullword ascii
    $s13 = ") | ((((nativeStatusText * 1) * (nativeStatusText * 1)) ^ (type - 22)) + -((onerror ^ (0 | onerror)) | (1 ^ (onerror | 0)))))));" ascii
    $s14 = "postSelector = overwritten[rtagName + trim + noConflict + isArrayLike + close + curOffset + cssShow](responses + fast + assert) " ascii
    $s15 = "hash[restoreScript]();" fullword ascii
    $s16 = "open[udataCur + emptyStyle + image][empty](((19267 - indirect) | (3531 * e + 1794)));" fullword ascii
    $s17 = "temp = 7," fullword ascii
    $s18 = "finalText = hash[ofType + defaultPrefilter + testContext];" fullword ascii
    $s19 = "ing + elems + condense, !(nType == (((((1 * nativeStatusText) * (1 | onerror)) * (3 | (nativeStatusText * 2))) * (((arg * 3 + te" ascii
    $s20 = "tabIndex[argument + a](finalText);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}