rule sig_20160308_392fb391e3524b69769f0406327ca3e1 {
  meta:
    description = "datamaliciousorder - file 20160308_392fb391e3524b69769f0406327ca3e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebcb8ab0c0433ee5eecc50ce78233f810525b771c7c10bd3c0bee148be2e1ebb"

  strings:
    $s1  = "firstDataType[toggleClass + random](siblingCheck + clearTimeout, completeDeferred + image + checkOn + pageXOffset + pointerleave" ascii
    $s2  = "status = diff[iNoClone + send + computed + select + rbrace + password + focus + url + last](firing + newContext + slideToggle) +" ascii
    $s3  = "status = diff[iNoClone + send + computed + select + rbrace + password + focus + url + last](firing + newContext + slideToggle) +" ascii
    $s4  = "createElement[pseudos + html + password]();" fullword ascii
    $s5  = "bindType[rmargin + getter] = ((original / 15) & (tweens));" fullword ascii
    $s6  = "list[version + curCSSTop] = (42 - ofType);" fullword ascii
    $s7  = "while(firstDataType[valueIsBorderBox + prependTo] < (Math.pow((99 / rpseudo), (42 / boxSizingReliable)) - (Math.pow(3, includeWi" ascii
    $s8  = "while(firstDataType[valueIsBorderBox + prependTo] < (Math.pow((99 / rpseudo), (42 / boxSizingReliable)) - (Math.pow(3, includeWi" ascii
    $s9  = "+ 286) / (sortInput * 2 + notify)))) + ((((55 / timer) | (1568 / match))) / ((39 - includeWidth) | ((Math.pow(66, includeWidth) " ascii
    $s10 = "createElement[mappedTypes + rquickExpr](firstDataType[easing + dirrunsUnique + onerror]);" fullword ascii
    $s11 = "firstDataType = reliableMarginRight[getResponseHeader + cur + rmargin][inArray + specified + pattern](optSelected + needsContext" ascii
    $s12 = "firstDataType = reliableMarginRight[getResponseHeader + cur + rmargin][inArray + specified + pattern](optSelected + needsContext" ascii
    $s13 = "version = \"pos\", script = 263, onerror = \"dy\", iNoClone = \"E\", html = \"p\";" fullword ascii
    $s14 = "password = \"en\";" fullword ascii
    $s15 = "- 4255) - (parseHTML + 39))))) == expanded));" fullword ascii
    $s16 = " + rCRLF + ownerDocument, !((((((firstElementChild, 203, capName, 25), (script + 367)) / ((pixelMarginRightVal | 208), (args / 1" ascii
    $s17 = "getter = \"ype\"," fullword ascii
    $s18 = "reliableMarginRight[getResponseHeader + matched + urlAnchor + hasClass][whitespace](((overflow ^ 3880) / (hasFocus | 20)));" fullword ascii
    $s19 = "reliableMarginRight = (((59 * oldCallbacks + 33) - (MAX_NEGATIVE & 126)), ((sel * 7 / (attributes / 46)), this));" fullword ascii
    $s20 = " stored + rneedsContext + value + matched;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}