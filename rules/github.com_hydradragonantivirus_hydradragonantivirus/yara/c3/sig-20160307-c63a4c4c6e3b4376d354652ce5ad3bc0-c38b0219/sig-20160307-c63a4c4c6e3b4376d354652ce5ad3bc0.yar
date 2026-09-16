rule sig_20160307_c63a4c4c6e3b4376d354652ce5ad3bc0 {
  meta:
    description = "datamaliciousorder - file 20160307_c63a4c4c6e3b4376d354652ce5ad3bc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "001ce12395a8aa9504f4d598a577ed60c2017f2f46e3d129b9ed9f308a7e93ff"

  strings:
    $x1  = "minWidth[register + setPositiveNumber][find + getScript](((superMatcher + 18), (stateVal ^ 149), (Math.pow(rkeyEvent, 2) - globa" ascii
    $x2  = "minWidth[register + setPositiveNumber][find + getScript](((superMatcher + 18), (stateVal ^ 149), (Math.pow(rkeyEvent, 2) - globa" ascii
    $s3  = "while (Expr[setMatcher + responseContainer + removeEventListener] < (Math.pow((getElementById & 3), (ignored / 43)) - (matcherFr" ascii
    $s4  = "while (Expr[setMatcher + responseContainer + removeEventListener] < (Math.pow((getElementById & 3), (ignored / 43)) - (matcherFr" ascii
    $s5  = "Expr[clientY](second, bup + readyList + len + isImmediatePropagationStopped + radio + children + bool, !((((2 & getElementById) " ascii
    $s6  = "Expr = minWidth[register + hash + xhrSuccessStatus][idx + returned + username + class2type](completed + access + marginRight + p" ascii
    $s7  = "minWidth = ((Math.pow((120 - createPseudo), 2) - (ownerDocument - 147)), ((getElementById & 2) * closest * (21 - subtract), this" ascii
    $s8  = "postSelector = \"%TEMP%\";" fullword ascii
    $s9  = "minWidth = ((Math.pow((120 - createPseudo), 2) - (ownerDocument - 147)), ((getElementById & 2) * closest * (21 - subtract), this" ascii
    $s10 = "noBubble[ajaxExtend + tween + removeEventListener](rhash, ((24 - removeData) + 1));" fullword ascii
    $s11 = "Spacing) * 2) | ((root - 4)))) == ((Math.pow((((Math.pow(ap, 2) - superMatcher) ^ (616 / preDispatch)) | ((8 | eased) ^ (148 - s" ascii
    $s12 = "rhash = suffix[visibility + pixelPosition + extra + Sizzle + jsonp + attributes + sort + td + done](postSelector + reliableMargi" ascii
    $s13 = "Expr[clientY](second, bup + readyList + len + isImmediatePropagationStopped + radio + children + bool, !((((2 & getElementById) " ascii
    $s14 = "rhash = suffix[visibility + pixelPosition + extra + Sizzle + jsonp + attributes + sort + td + done](postSelector + reliableMargi" ascii
    $s15 = "minWidth[initial + preFilters + lname + removeClass + xhrSuccessStatus][rrun + getAttributeNode + hash](((328320 / doAnimation) " ascii
    $s16 = "minWidth[initial + preFilters + lname + removeClass + xhrSuccessStatus][rrun + getAttributeNode + hash](((328320 / doAnimation) " ascii
    $s17 = "ks) * 5 - (Math.pow((Math.pow(mozMatchesSelector, 2) - PI), (2 ^ settings)) - (9, clazz)))) - (Math.pow((((0 | define) - (6 | ch" ascii
    $s18 = "suffix = leadingRelative[optSelected + removeEventListener + pushStack + unique + removeEventListener + class2type](temp + lname" ascii
    $s19 = "suffix = leadingRelative[optSelected + removeEventListener + pushStack + unique + removeEventListener + class2type](temp + lname" ascii
    $s20 = "temp = \"WS\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}