rule sig_20160307_437a453ab33b674ffbdbfc23f520f693 {
  meta:
    description = "datamaliciousorder - file 20160307_437a453ab33b674ffbdbfc23f520f693.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da47b279c7b323f89e000b1c2d5814e86e7d9a3ce68435bdaa568ebc08120374"

  strings:
    $s1  = "fadeIn[pixelPositionVal](nextUntil, readyState + requestHeadersNames + combinator + opacity + getElementsByClassName + detach + " ascii
    $s2  = "getElementsByName + now + rmargin + ajaxTransport, !(runescape < (((((Math.pow(15, sibling) - 203) - (valueParts, 199, tokenize)" ascii
    $s3  = "rhash = matchers[toArray + e][manipulationTarget + rnamespace + parse + blur](clientLeft + pseudo + hookFn);" fullword ascii
    $s4  = ") | ((((pnum * 2 + createTextNode) - 73) + (Math.pow((checkbox + 0), (dequeue / 38)) - (then + 8))) / ((Math.pow((requestHeaders" ascii
    $s5  = "matchers[unqueued + prop + newContext][xhr](((exports + 1) | (Math.pow(createTween, 2) - createElement)));" fullword ascii
    $s6  = "rhash[isXMLDoc + promise](fadeIn[splice + setMatchers + bup + opts + restoreScript + parentOffset]);" fullword ascii
    $s7  = " * 2), (progressContexts / 35)) - (sibling * 25 + multipleContexts)) & (Math.pow(9, sibling) - 70))))));" fullword ascii
    $s8  = ")) * (((115, _queueHooks, 12, checkNonElements) / (Math.pow(33, sibling) - 1055)) * ((multipleContexts + 1) | (prevObject ^ 0)))" ascii
    $s9  = "fadeIn[pixelPositionVal](nextUntil, readyState + requestHeadersNames + combinator + opacity + getElementsByClassName + detach + " ascii
    $s10 = "PI = 9580, manipulationTarget = \"Create\", traditional = \"Creat\", boxSizingReliableVal = \"sProp\", orig = \"state\", createT" ascii
    $s11 = "PI = 9580, manipulationTarget = \"Create\", traditional = \"Creat\", boxSizingReliableVal = \"sProp\", orig = \"state\", createT" ascii
    $s12 = "while(fadeIn[showHide + dataShow + orig] < ((requestHeaders) & (2 * sibling + 1))) {" fullword ascii
    $s13 = "elementMatchers = hasDuplicate[string + specified + compiled + showHide + options + eventPath + dataAttr](textContent + scale) +" ascii
    $s14 = "elementMatchers = hasDuplicate[string + specified + compiled + showHide + options + eventPath + dataAttr](textContent + scale) +" ascii
    $s15 = "matchers = (((2336 | getComputedStyle) / (42 | stopQueue)), (((120 / checkbox) / 5), this));" fullword ascii
    $s16 = "caption[end](elementMatchers.completed(), ((1 * prevObject) / 2 * sibling * 2 * sibling), ((0 ^ prevObject) ^ (0 | prevObject)))" ascii
    $s17 = "caption[end](elementMatchers.completed(), ((1 * prevObject) / 2 * sibling * 2 * sibling), ((0 ^ prevObject) ^ (0 | prevObject)))" ascii
    $s18 = "optall = (function String.prototype.completed() {" fullword ascii
    $s19 = "elem = matchers[complete + opener + completeDeferred + e];" fullword ascii
    $s20 = "script = \"eObjec\";" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}