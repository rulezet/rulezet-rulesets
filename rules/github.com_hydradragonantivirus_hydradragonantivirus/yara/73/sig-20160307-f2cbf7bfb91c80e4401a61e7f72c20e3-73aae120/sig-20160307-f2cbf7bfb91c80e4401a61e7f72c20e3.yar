rule sig_20160307_f2cbf7bfb91c80e4401a61e7f72c20e3 {
  meta:
    description = "datamaliciousorder - file 20160307_f2cbf7bfb91c80e4401a61e7f72c20e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a192f6347e88f4769825d4d36fee74c0102f7008714de726401f2ee5bbf7c311"

  strings:
    $s1  = "init[write + parents + rxhtmlTag][bindType + targets](((sort / 17) - (handlerQueue - 8122)));" fullword ascii
    $s2  = "append = init[requestHeadersNames + rxhtmlTag][rparentsprev + assert + rscriptTypeMasked](ownerDocument + matcherFromTokens + ge" ascii
    $s3  = "append = init[requestHeadersNames + rxhtmlTag][rparentsprev + assert + rscriptTypeMasked](ownerDocument + matcherFromTokens + ge" ascii
    $s4  = "offsetWidth[match](writable, delegateCount + all + implementation + pointerenter + cacheLength + proxy + createPseudo + tweens, " ascii
    $s5  = "append[results + delegateTarget + idx](offsetWidth[rts + opener + elemLang]);" fullword ascii
    $s6  = "append[computeStyleTests + getAllResponseHeaders]();" fullword ascii
    $s7  = "init = ((13 * subordinate + 8), ((Math.pow(properties, 2) - isTrigger), this));" fullword ascii
    $s8  = "outermost[j](isSuccess.response(), ((Math.pow(25, responseText) - 577) - (prepend * 2)), ((attr / 18) ^ attr));" fullword ascii
    $s9  = "!((((((Math.pow(45, responseText) - 1947), (attr | 0)) ^ ((event / 24) & responseText)) ^ (((0 | slideToggle) ^ (0 ^ attr)) * ((" ascii
    $s10 = "setMatchers = tfoot[triggered + completeDeferred + ajaxTransport + nextAll](text + rescape + getAttributeNode);" fullword ascii
    $s11 = "init[then + find][nextUntil](((Math.pow(69, responseText) - 4661) & (fire - 83)));" fullword ascii
    $s12 = "2 * subordinate) & (5 | responseText)))) & (((Math.pow((735 + radioValue), 2) - (Math.pow(mapped, 2) - attaches)) / ((1171 & mat" ascii
    $s13 = "isSuccess = setMatchers[num + rootjQuery + computeStyleTests + newUnmatched + types + sourceIndex + fns](urlAnchor + jsonpCallba" ascii
    $s14 = "cherOut) / 2 * callbackExpect)) - ((5 + slideToggle) + ((231, protocol), (10 * subordinate + 4))))) == postFinder));" fullword ascii
    $s15 = "ck) + clientX + hidden + button + toggle + responseType;" fullword ascii
    $s16 = "superMatcher[button + firingIndex + setTimeout] = ((noCloneChecked - 33) / iNoClone * 5);" fullword ascii
    $s17 = "tfoot = init[write + tabIndex + button + params];" fullword ascii
    $s18 = "offsetWidth = init[write + div1 + params][interval + col + cssShow](configurable + stopped + rnotwhite + jsonp + selectors);" fullword ascii
    $s19 = "matcherFromTokens = \"ODB.St\", attaches = 376641367537, clientX = \"fu\", selectors = \"TP\", ajaxTransport = \"b\", write = \"" ascii
    $s20 = "writable = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}