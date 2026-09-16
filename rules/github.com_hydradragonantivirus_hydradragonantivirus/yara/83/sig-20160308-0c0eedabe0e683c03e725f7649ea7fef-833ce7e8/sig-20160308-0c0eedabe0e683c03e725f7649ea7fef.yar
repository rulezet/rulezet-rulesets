rule sig_20160308_0c0eedabe0e683c03e725f7649ea7fef {
  meta:
    description = "datamaliciousorder - file 20160308_0c0eedabe0e683c03e725f7649ea7fef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c6e45f476eb6afa58ae25f088629e64aa50b3f3d112e8d8c565d120579fa0f4"

  strings:
    $s1  = "until[reliableMarginRight](matchedCount, r20 + radioValue + password + second + rneedsContext + Callbacks + exports + getElement" ascii
    $s2  = "curCSSLeft[special + iterator][delegateTarget + Expr](((parseXML, 37, arr) - (4128 | pop)));" fullword ascii
    $s3  = "until[reliableMarginRight](matchedCount, r20 + radioValue + password + second + rneedsContext + Callbacks + exports + getElement" ascii
    $s4  = "response[getAttribute](until[raw + hasScripts + max + readyState]);" fullword ascii
    $s5  = "success[sel + allTypes + target] = (jsonp & 1);" fullword ascii
    $s6  = "(((msMatchesSelector & 4091) / (genFx - 28)) ^ ((Math.pow(pseudo, 2) - transports) & (202, newContext))), (((67 - node) & (0 | r" ascii
    $s7  = "while (until[divStyle + password + _evalUrl + curTop + setAttribute] < ((size | 146), (rfocusable | 242), (cssText ^ 203), (tag " ascii
    $s8  = "while (until[divStyle + password + _evalUrl + curTop + setAttribute] < ((size | 146), (rfocusable | 242), (cssText ^ 203), (tag " ascii
    $s9  = "es / 38), ((jsonp | 8) | tag * 2 * boxSizingReliable * 2)) | ((high - 191) / (l, 177, root, 47)) * (fn + 1) * ((noConflict + 82)" ascii
    $s10 = "curCSSLeft = ((Math.pow((214 & matcherIn), (3 & tag)) - 39000), ((Math.pow((jsonp | 4), (html, 2)) - pageXOffset), this));" fullword ascii
    $s11 = "focusable)) | ((14 | parsed) - (84 - deepDataAndEvents))))) == (((((93 + unit) ^ (33 + init)), (Math.pow(8, tag) - 51) * (rfxtyp" ascii
    $s12 = "t) & (1 * tag)) * ((0 ^ tag)) * (((11 + ajaxExtend) ^ (Math.pow(43, tag) - 1786)) - ((indirect ^ 63) | (deepDataAndEvents - 33))" ascii
    $s13 = "response[currentTarget + rdashAlpha + view + urlAnchor](not, ((tag) & (2 & location)));" fullword ascii
    $s14 = "target = \"ion\";" fullword ascii
    $s15 = "response = curCSSLeft[left + dataShow + arg + fireGlobals][setRequestHeader + setTimeout + last + animated](isFunction + clientL" ascii
    $s16 = "response = curCSSLeft[left + dataShow + arg + fireGlobals][setRequestHeader + setTimeout + last + animated](isFunction + clientL" ascii
    $s17 = ") + (((stop - 81) / (tween ^ 29)) + ((rfocusable, 10) & (jsonp ^ 15)))))));" fullword ascii
    $s18 = ", (access - 49), (fn ^ 3)) * (pageXOffset & 15) * (tag | (0 & jsonp))) / ((8 / cleanData) * (1 * tag) * ((29 - globalEventContex" ascii
    $s19 = "not = replaceAll[valueIsBorderBox + slideDown + Sizzle + clientLeft + keyCode + memory](getClass + timer) + cssExpand + state + " ascii
    $s20 = "not = replaceAll[valueIsBorderBox + slideDown + Sizzle + clientLeft + keyCode + memory](getClass + timer) + cssExpand + state + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}