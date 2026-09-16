rule sig_20160309_48a24a58cb7b5a568cabd52e9b6dc523 {
  meta:
    description = "datamaliciousorder - file 20160309_48a24a58cb7b5a568cabd52e9b6dc523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "088e2b68f2c2f1172c894e1e07f435c09f079d3230cb069c6ef053a21bf7ef21"

  strings:
    $s1  = "readyWait[clearQueue](rsubmittable, timeStamp + div1 + next + checkNonElements + win + filters + timeStamp + removeChild + orig " ascii
    $s2  = "toSelector = readyWait[apply + relatedTarget + bySet + completeDeferred + readyList + matcher];" fullword ascii
    $s3  = "readyWait = postFilter[value + createComment][srcElements + superMatcher + splice + superMatcher + get](acceptData + temp + rbug" ascii
    $s4  = "readyWait = postFilter[value + createComment][srcElements + superMatcher + splice + superMatcher + get](acceptData + temp + rbug" ascii
    $s5  = "rscriptTypeMasked = postFilter[preFilter + arr + div1];" fullword ascii
    $s6  = " ((Math.pow((Math.pow((index | 72), overflowX) - (3713 + emptyGet)), ((34 + abort) - (48 & cached))) - ((4556 | setMatcher) - (M" ascii
    $s7  = "postFilter[type + startLength][makeArray + isLocal](((insertBefore - 7821) & (contexts | 15250)));" fullword ascii
    $s8  = "postFilter = (((35 + animate) + (2600 / traditional)), (((2210 / selectedIndex) / (26 + curLeft)), this));" fullword ascii
    $s9  = "match = postFilter[clearTimeout + div1][curValue + dir + selection + div1](fragment + responseFields + replaceAll);" fullword ascii
    $s10 = "_data = merge[crossDomain + stateString + isBorderBox + escaped + els + root](contents + option + ct) + trim + firstChild + attr" ascii
    $s11 = "_data = merge[crossDomain + stateString + isBorderBox + escaped + els + root](contents + option + ct) + trim + firstChild + attr" ascii
    $s12 = "temp = \"L2.XM\";" fullword ascii
    $s13 = "readyWait[clearQueue](rsubmittable, timeStamp + div1 + next + checkNonElements + win + filters + timeStamp + removeChild + orig " ascii
    $s14 = "bySet = \"p\", index = 97, startLength = \"Script\";" fullword ascii
    $s15 = "merge = rscriptTypeMasked[class2type + specified + minWidth](type + startLength + rnative + done);" fullword ascii
    $s16 = " contents = \"%T\"," fullword ascii
    $s17 = "remaining[div1 + matcher + html] = 1;" fullword ascii
    $s18 = "match[shift + blur](toSelector);" fullword ascii
    $s19 = "removeAttr = apply + setTimeout;" fullword ascii
    $s20 = "view[attrHooks + superMatcher]();" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}