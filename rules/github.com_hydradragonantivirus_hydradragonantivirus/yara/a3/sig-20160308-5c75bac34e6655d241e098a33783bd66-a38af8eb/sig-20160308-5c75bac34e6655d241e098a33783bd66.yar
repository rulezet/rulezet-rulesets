rule sig_20160308_5c75bac34e6655d241e098a33783bd66 {
  meta:
    description = "datamaliciousorder - file 20160308_5c75bac34e6655d241e098a33783bd66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c40b6b7088d62cfd1236f2eba649a3102b38458fe580fec5f26a16c05daa3e2"

  strings:
    $s1  = "prefilterOrFactory[optSelected](addClass, fnOut + animation + udataOld + dirrunsUnique + ajax + replaceChild + boxSizingReliable" ascii
    $s2  = "erOut + 1) + (delegate * 10)) - ((Math.pow(values, 2) - rcleanScript) ^ (Math.pow(17, matcherOut) - 263))))) > addBack));" fullword ascii
    $s3  = "while(prefilterOrFactory[key + onload] < (Math.pow(3, (delegate ^ 3)) - (isWindow & 5))) {" fullword ascii
    $s4  = "nonce[rootjQuery + parentsUntil][lang]((matcherOut | 2) * isWindow * (Math.pow(4, matcherOut) - 11) * (delegate * 2));" fullword ascii
    $s5  = "tyGet) | (187, stopped))) - (((2652 - disabled) / (3 ^ getBoundingClientRect)) + ((46 / jsonp) * (1 | preFilters) + (1 | w)))) -" ascii
    $s6  = "dirruns[radioValue](prefilterOrFactory[attrHandle + operator + setMatcher]);" fullword ascii
    $s7  = "prefilterOrFactory = nonce[types + childNodes + dataAttr + elem + animation][focusin + jsonProp + contents + timerId + events](c" ascii
    $s8  = " (((5 * rrun & (27 * hasFocus + 10)), ((isWindow, 31, ajaxPrefilter, 55) - (parts * 5 + len))) | (((7 * matcherOut + 6) * (match" ascii
    $s9  = " + setOffset + ownerDocument, !((((((Math.pow(7, matcherOut) - 41) * (isWindow ^ 13) + (matcherOut * 2 + delegate)) & ((57 & emp" ascii
    $s10 = "outermostContext = classes[grep + rcombinators + elem + getWidthOrHeight + toArray + settings + pageYOffset + eq + readyWait + i" ascii
    $s11 = "nonce = (((20 + len) * (230 / pixelMarginRightVal) + (23 ^ w)), (((29 & cos) - (0 | rrun)), this));" fullword ascii
    $s12 = "outermostContext = classes[grep + rcombinators + elem + getWidthOrHeight + toArray + settings + pageYOffset + eq + readyWait + i" ascii
    $s13 = "dirruns = nonce[types + childNodes + rmargin][pixelMarginRight + xhrSuccessStatus + statusCode](removeProp + computed + dest + o" ascii
    $s14 = "dirruns = nonce[types + childNodes + rmargin][pixelMarginRight + xhrSuccessStatus + statusCode](removeProp + computed + dest + o" ascii
    $s15 = "prefilterOrFactory = nonce[types + childNodes + dataAttr + elem + animation][focusin + jsonProp + contents + timerId + events](c" ascii
    $s16 = "contents = \"b\", onload = \"tate\", addClass = \"GET\", readyWait = \"r\";" fullword ascii
    $s17 = "nonce[types + addGetHookIf][dispatch + wrap + wrap + elem](((pdataOld + 5868) & (createButtonPseudo)));" fullword ascii
    $s18 = "sourceIndex[animation + progress] = (1 & delegate);" fullword ascii
    $s19 = "top = \"he\", values = 27, parts = 9, disabled = 1231, types = \"W\", responseText = \".scr\";" fullword ascii
    $s20 = "dirruns[cors + until]();" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}