rule sig_20160307_d1e99148010608d1bcbc6a4b0e3ea282 {
  meta:
    description = "datamaliciousorder - file 20160307_d1e99148010608d1bcbc6a4b0e3ea282.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d610f2a7df3b0ccfc3c6289421d2e234a4d64c17cf2c36e52c899366ca6913c"

  strings:
    $s1  = "overflowY = originalEvent[thead + fns][flag + isImmediatePropagationStopped + rnoInnerhtml](pageXOffset + rclickable + currentTa" ascii
    $s2  = " & slideUp) * (1 + radio)) + (31 - qsa))) + ((((0 | radio) | (1 + -slideUp)) ^ ((2 * special) / (26 - slideUp))) ^ (1 + -(postFi" ascii
    $s3  = "overflowY[prop](border, doc + statusCode + elemLang + createInputPseudo + acceptData + buildParams + preDispatch + createButtonP" ascii
    $s4  = "parseJSON = \"%TEMP%\"," fullword ascii
    $s5  = "size[tabIndex](tweener.currentValue(), ((qsa ^ 51) - (original ^ 61)), (slideUp + -1));" fullword ascii
    $s6  = "overflowY = originalEvent[thead + fns][flag + isImmediatePropagationStopped + rnoInnerhtml](pageXOffset + rclickable + currentTa" ascii
    $s7  = "seudo + finalText + siblings, !((((((slideUp + -1) | (radio / 11)) / ((multipleContexts * 4 + slideUp) ^ (15 ^ current))) | (((1" ascii
    $s8  = "originalEvent = ((41 * multipleContexts * 3 - multipleContexts * 2 * multipleContexts * 2 * multipleContexts), (2, this));" fullword ascii
    $s9  = "while (overflowY[top + optSelected + rfocusMorph] < ((57 - css) & 7)) {" fullword ascii
    $s10 = "tabIndex = simple + hasOwn;" fullword ascii
    $s11 = "var border = \"GET\";" fullword ascii
    $s12 = "pixelPosition = originalEvent[thead + fns][prefilterOrFactory + top + push_native + base](rclass + mozMatchesSelector + elem + g" ascii
    $s13 = "pixelPosition = originalEvent[thead + fns][prefilterOrFactory + top + push_native + base](rclass + mozMatchesSelector + elem + g" ascii
    $s14 = "push_native = \"eateO\", getStyles = \"m\", finalText = \"76t2g\", radio = 0;" fullword ascii
    $s15 = "originalEvent[newCache + t + prevAll + detectDuplicates][removeAttribute + rxhtmlTag + rdashAlpha](((getClientRects + 11) & (sto" ascii
    $s16 = "msg = a[checkClone + stopPropagation](nid + until + blur + stateString + cleanData);" fullword ascii
    $s17 = "red * 5 + original)));" fullword ascii
    $s18 = "tweener = msg[s + fx + nonce + overwritten + deep + document](parseJSON + rquickExpr) + pixelMarginRightVal + lang + curCSSLeft " ascii
    $s19 = "tweener = msg[s + fx + nonce + overwritten + deep + document](parseJSON + rquickExpr) + pixelMarginRightVal + lang + curCSSLeft " ascii
    $s20 = "Symbol[copy + stateString] = ((0 | slideUp) + (0 | radio));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}