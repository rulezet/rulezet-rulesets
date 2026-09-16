rule sig_20160309_bc862b98b4de2a7492f1d972af47812b {
  meta:
    description = "datamaliciousorder - file 20160309_bc862b98b4de2a7492f1d972af47812b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e3cd7bc073be0902aaa93ffd27e0a7adbe79a1b32d4648ceb82749997dfec70"

  strings:
    $s1  = "origCount = options[inspected + password][andSelf + getAllResponseHeaders + matchIndexes + dataTypeExpression](triggered + prope" ascii
    $s2  = "ashAlpha))) | (((345 - doc), (3510 / returnValue), 193, (appendTo, 145)), ((dirruns ^ 226) | (xhrSupported * 2 + proxy)), (0 ^ (" ascii
    $s3  = "options[inspected + password][opener + input](((206379 - time) / (11 & url)));" fullword ascii
    $s4  = "origCount[padding](match, dataAttr + nextUntil + evt + rhtml + guaranteedUnique + hasDuplicate + JSON + clearCloneStyle + deep +" ascii
    $s5  = "isBorderBox = options[which + pageYOffset][andSelf + getAllResponseHeaders + isReady + preferredDoc + notify + compareDocumentPo" ascii
    $s6  = "isBorderBox = options[which + pageYOffset][andSelf + getAllResponseHeaders + isReady + preferredDoc + notify + compareDocumentPo" ascii
    $s7  = "origCount = options[inspected + password][andSelf + getAllResponseHeaders + matchIndexes + dataTypeExpression](triggered + prope" ascii
    $s8  = "mimeType = \"n\", rdashAlpha = 1, getText = \"gin\", password = \"ript\", max = \"oFile\", cleanData = \"ings\";" fullword ascii
    $s9  = " - props)) ^ ((Math.pow(9, win) - 71) | win)) - (((0 ^ map) ^ (0 / returnValue)) + (2 & jsonp) * (35 - reject)))) == 2));" fullword ascii
    $s10 = "size = _[rquery + boxSizingReliableVal + setter + notify + trim + cleanData](className + camel) + createComment + tokenize + imp" ascii
    $s11 = "rquery = \"Expan\", compiled = \"Respo\", delegateCount = \"L\", match = \"GET\", win = 2, dirruns = 97;" fullword ascii
    $s12 = "_ = results[serialize + responseHeaders + dataTypeExpression](state + chainable + duration);" fullword ascii
    $s13 = " elems + bubbleType + id + fadeToggle + high + module, !((((((1 + -rdashAlpha) ^ (45 - unmatched)) & ((1 * rdashAlpha) * (0 | rd" ascii
    $s14 = "isBorderBox[slideUp + tbody + max](size, ((1 * newDefer) / (34 - returnValue)));" fullword ascii
    $s15 = "size = _[rquery + boxSizingReliableVal + setter + notify + trim + cleanData](className + camel) + createComment + tokenize + imp" ascii
    $s16 = "options = (((7332 / inspect), (45 ^ responseFields)), ((1 + (defineProperty, 185, props)), this));" fullword ascii
    $s17 = "isBorderBox[timeoutTimer + set + notify](isNumeric);" fullword ascii
    $s18 = "bool[not](size.stopPropagation(), ((24, beforeSend, 126, rdashAlpha) * (0 ^ constructor)), (1 * (constructor | 0)));" fullword ascii
    $s19 = "sition](activeElement + percent + curPosition + radioValue);" fullword ascii
    $s20 = "bp[rpseudo + notify]();" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}