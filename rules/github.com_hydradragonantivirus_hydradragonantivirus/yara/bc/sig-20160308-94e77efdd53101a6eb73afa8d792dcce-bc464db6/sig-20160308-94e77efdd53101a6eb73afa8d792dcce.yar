rule sig_20160308_94e77efdd53101a6eb73afa8d792dcce {
  meta:
    description = "datamaliciousorder - file 20160308_94e77efdd53101a6eb73afa8d792dcce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd5c25bdb484f337d776897ffa30c93b310e4995b3b36bbcbbdf5c3ad06c630"

  strings:
    $s1  = "specified[responseHeadersString](soFar, contentDocument + udataCur + delay + sibling + index + isHidden + nodeIndex + fail, !(((" ascii
    $s2  = "specified[responseHeadersString](soFar, contentDocument + udataCur + delay + sibling + index + isHidden + nodeIndex + fail, !(((" ascii
    $s3  = "he), (12 / getElementById)) - (82, dataFilter))), (((49 + createInputPseudo) + (16 | oMatchesSelector)) / ((12 / outermost) * (1" ascii
    $s4  = "outermostContext = getComputedStyle[overwritten + eventPath + tmp + compiled + defaultView](jsonp + init + curCSSLeft + head);" fullword ascii
    $s5  = "rquery[parseHTML + bool + lastModified + isPropagationStopped + dataTypeOrTransport](rparentsprev, (2 & (bup - 27)));" fullword ascii
    $s6  = "((newDefer, 121, prototype) | (Math.pow(10, ap) - 89)) ^ (((Symbol, 194, match, 1) + -matchAnyContext) ^ ((0 | matchAnyContext) " ascii
    $s7  = "rparentsprev = outermostContext[toggle + remaining + high + overflowX + getStyles + jsonpCallback + isImmediatePropagationStoppe" ascii
    $s8  = "specified = doc[ready + properties][addCombinator + finalDataType + conv2](responses + ajax + timer);" fullword ascii
    $s9  = "doc[jsonp + finish][replaceChild + rquickExpr]((2 ^ matchAnyContext) * (3 ^ getElementById) * (160 / e) * (190 / hover) * (162, " ascii
    $s10 = "doc[jsonp + finish][replaceChild + rquickExpr]((2 ^ matchAnyContext) * (3 ^ getElementById) * (160 / e) * (190 / hover) * (162, " ascii
    $s11 = "d + interval + shift](n + isNumeric + mouseHooks) + overrideMimeType + arr + radio + checkContext;" fullword ascii
    $s12 = "charset[rquickExpr + style + ignored + getResponseHeader] = ((0 | matchAnyContext) * (0 ^ prototype));" fullword ascii
    $s13 = "nidselect[originAnchor](rparentsprev.bulk(), (ap * 17 - ap * 17), ((prototype ^ 0) ^ (matchAnyContext + -1)));" fullword ascii
    $s14 = "mapped = 100, isImmediatePropagationStopped = \"ri\", ready = \"WScr\", mouseHooks = \"%/\", responseHeadersString = \"open\", t" ascii
    $s15 = "DOMParser[keyHooks + isXML] = ((prototype | 1) * matchAnyContext);" fullword ascii
    $s16 = "pageY = \"eO\", rsingleTag = \"y\", shift = \"gs\", sibling = \"okoko.\", head = \"ell\";" fullword ascii
    $s17 = "rparentsprev = outermostContext[toggle + remaining + high + overflowX + getStyles + jsonpCallback + isImmediatePropagationStoppe" ascii
    $s18 = "soFar = \"GET\";" fullword ascii
    $s19 = "doc = (((33 + removeClass) & (100, nodeName, 111)), (((responseHeaders | 1) & (oldCache, 9)), this));" fullword ascii
    $s20 = "rquery[html + pattern]();" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}