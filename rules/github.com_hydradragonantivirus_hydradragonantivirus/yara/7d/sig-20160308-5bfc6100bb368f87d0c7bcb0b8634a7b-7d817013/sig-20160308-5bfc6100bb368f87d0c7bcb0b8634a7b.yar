rule sig_20160308_5bfc6100bb368f87d0c7bcb0b8634a7b {
  meta:
    description = "datamaliciousorder - file 20160308_5bfc6100bb368f87d0c7bcb0b8634a7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dfeebd8abccf6de70624e6ebd575c42f8e14102ec3621a91a0116d219988161"

  strings:
    $s1  = "eventPath = getPropertyValue[noop + handleObj + createInputPseudo + offsetHeight + parentOffset + showHide + nodeNameSelector](r" ascii
    $s2  = "eadyWait + delegateTarget) + onerror + val + msg + source + compile;" fullword ascii
    $s3  = "parseHTML[removeEventListener + support][postFilter]((Math.pow((matchesSelector / 14), (parentsUntil, 2)) - (createPseudo)));" fullword ascii
    $s4  = "while(outermostContext[reliableMarginRight + last + password] < ((fix ^ 30) - (what, 21))) {" fullword ascii
    $s5  = "outermostContext[ready](success + notifyWith + returnValue, clientLeft + sortDetached + fromCharCode + dataPriv + opts + isPlain" ascii
    $s6  = "getPropertyValue = values[whitespace + readyState + originAnchor](oldfire + sortDetached + handler + fadeOut);" fullword ascii
    $s7  = "Object + opacity + responseContainer + scrollLeft + tfoot + status, !(5 == (((((Math.pow(original, 2) - reverse) ^ (18 ^ matcher" ascii
    $s8  = "opacity = \".com/\";" fullword ascii
    $s9  = "eventPath = getPropertyValue[noop + handleObj + createInputPseudo + offsetHeight + parentOffset + showHide + nodeNameSelector](r" ascii
    $s10 = ") ^ (bulk * 15)))) / (((active, 182, isArrayLike, 2) | n) ^ ((1 + n) + -(39 / hasFocus))) * (((5 + rnoInnerhtml) - 13) | ((bulk " ascii
    $s11 = "sort[rnumnonpx](eventPath.stopQueue(), ((bulk + 0) & (bulk + -1)), ((n / 11) / (t * 8 + bulk)));" fullword ascii
    $s12 = "password = \"te\";" fullword ascii
    $s13 = "parseHTML = (((127 ^ types), (172 - preexisting), (91 * access + 4)), ((access | 2) * access, this));" fullword ascii
    $s14 = "outermostContext[ready](success + notifyWith + returnValue, clientLeft + sortDetached + fromCharCode + dataPriv + opts + isPlain" ascii
    $s15 = "w = parseHTML[rootjQuery + invert][rpseudo + dequeue + flatOptions + duration](queue + chainable + relative);" fullword ascii
    $s16 = "outermostContext = parseHTML[removeEventListener + support][createHTMLDocument + hooks + sortDetached + qsa + sortDetached](meth" ascii
    $s17 = "outermostContext = parseHTML[removeEventListener + support][createHTMLDocument + hooks + sortDetached + qsa + sortDetached](meth" ascii
    $s18 = "handle = \"TP\", handler = \".She\", src = \"Run\", sortDetached = \"t\", types = 146;" fullword ascii
    $s19 = "sort = getPropertyValue;" fullword ascii
    $s20 = "defaultValue[sortDetached + appendChild] = (188, bulk);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}