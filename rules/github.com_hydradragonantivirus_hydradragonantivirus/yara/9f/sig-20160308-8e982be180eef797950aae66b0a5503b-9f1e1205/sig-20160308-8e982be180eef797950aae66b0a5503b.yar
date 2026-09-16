rule sig_20160308_8e982be180eef797950aae66b0a5503b {
  meta:
    description = "datamaliciousorder - file 20160308_8e982be180eef797950aae66b0a5503b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52d886acc7a36856ff8df1bf5cc665897cb6eece896438a2a848be09aff439a1"

  strings:
    $s1  = "mouseHooks[toggleClass + ready](matcher, curLeft + unquoted + parseXML + step + prevUntil + globalEventContext + module + matche" ascii
    $s2  = "overflowY = excess[actualDisplay + _jQuery + host + responseHeadersString + keepScripts + selectedIndex](stateString + pattern +" ascii
    $s3  = "overflowY = excess[actualDisplay + _jQuery + host + responseHeadersString + keepScripts + selectedIndex](stateString + pattern +" ascii
    $s4  = "rFromTokens + setTimeout, !(soFar == (Math.pow(((((4 + offsetParent))) + (1 ^ ((thead, 185, isPlainObject, 0) ^ (sortOrder + -1)" ascii
    $s5  = "^ 2))))) - (((setRequestHeader / 31) - (targets / 23)) | ((makeArray | 0) ^ (index / 30)) * ((replaceAll - 61) - ajaxSettings * " ascii
    $s6  = "while (mouseHooks[rscriptTypeMasked + contains + focusin] < (subordinate - 47) * offsetParent) {" fullword ascii
    $s7  = "radio[remaining + content + preDispatch] = ((105, getStyles, 0) / (prefilterOrFactory, 50, click, 6));" fullword ascii
    $s8  = "))), ((Math.pow(((interval * 2 + sortOrder) ^ 2), (sortOrder + 1)) - ((getClass / 22) ^ (matchedCount * 16 + valueIsBorderBox)))" ascii
    $s9  = "maxIterations = rprotocol[getText + write + showHide][isBorderBox + letterSpacing](s + combinator + isSuccess + firingIndex);" fullword ascii
    $s10 = "minWidth[t](overflowY.ofType(), ((sortOrder & 1) + -sortOrder), ((0 | makeArray) / (34 - opener)));" fullword ascii
    $s11 = "maxIterations[round + aup + configurable + teardown]();" fullword ascii
    $s12 = " / ((Math.pow((120 - initialInUnit), (61, hasDuplicate, 2)) - (always, 209, rmouseEvent, 1876)) / ((makeArray | 1) ^ (makeArray " ascii
    $s13 = "maxIterations[stop](mouseHooks[wrapInner + configurable + left + args + ifModified]);" fullword ascii
    $s14 = "content = \"o\";" fullword ascii
    $s15 = "traditional[unloadHandler] = ((getPropertyValue, 155, sortOrder) ^ (0 | makeArray));" fullword ascii
    $s16 = "var matcher = \"GET\"," fullword ascii
    $s17 = "host = \"ronmen\";" fullword ascii
    $s18 = "rprotocol = (((13 * finalText + 11), (hidden ^ 195)), (((load ^ 4) ^ (selectors, 43, one, 13)), this));" fullword ascii
    $s19 = "3) * (sortOrder | 5) * ((handler / 31) + (sortOrder | 1))))));" fullword ascii
    $s20 = " simple) + adjustCSS + pointerleave + cors + implicitRelative + styles;" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}