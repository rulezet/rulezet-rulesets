rule sig_20160309_154f37be1498326c3b80bfc35f91a01d {
  meta:
    description = "datamaliciousorder - file 20160309_154f37be1498326c3b80bfc35f91a01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a27eabe4285a55381a5dcbfe9bc10584c2c42267061f17adc5761824542775a"

  strings:
    $s1  = "fns[hasScripts + isImmediatePropagationStopped + clientLeft][isDefaultPrevented + shift + getComputedStyle](((isHidden * 4), (sr" ascii
    $s2  = "fns[hasScripts + isImmediatePropagationStopped + clientLeft][isDefaultPrevented + shift + getComputedStyle](((isHidden * 4), (sr" ascii
    $s3  = "attrHandle[ajaxTransport](curOffset + abort, high + getComputedStyle + state + rwhitespace + rpseudo + mouseleave + cloneNode + " ascii
    $s4  = ", ((1 | second) - (Math.pow(9, getClientRects) - 65))) * (((getClientRects + 1)) & ((rmouseEvent, 99) / (getText ^ 42))))) == b)" ascii
    $s5  = " * 2 * ontype * 7 / (Math.pow(selected, 2) - value)), (Math.pow((10 ^ second), (2 | getClientRects)) - (173 ^ defaultPrevented))" ascii
    $s6  = " (until + 9), (Math.pow(throws, 2) - cssNumber), 2 * getClientRects)) * ((59 + (marginRight + 3)) / ((throws) - (199, msg, 171, " ascii
    $s7  = "attrHandle[ajaxTransport](curOffset + abort, high + getComputedStyle + state + rwhitespace + rpseudo + mouseleave + cloneNode + " ascii
    $s8  = "attrHandle = fns[hasScripts + soFar + pixelMarginRightVal][lang + preexisting + accepts](PI + rhash + active + anim);" fullword ascii
    $s9  = "fns = (((2520 / second) ^ (Math.pow(137, getClientRects) - 18519)), (((location / 14) * (checkDisplay & 7)), this));" fullword ascii
    $s10 = "eject + prevUntil + rcombinators + getElementById + a + elementMatcher + rchecked;" fullword ascii
    $s11 = "isLocal = td[oldfire + always + dataTypeExpression + computeStyleTests + handleObj + matched + rtrim](t + removeAttr) + pipe + r" ascii
    $s12 = "removeProp = fns[holdReady + focusin][Deferred + extend + clientTop + dataTypeOrTransport + a](responseContainer + key + using +" ascii
    $s13 = "removeProp = fns[holdReady + focusin][Deferred + extend + clientTop + dataTypeOrTransport + a](responseContainer + key + using +" ascii
    $s14 = "removeProp[rtrim + rcleanScript + rdashAlpha + suffix](isLocal, ((timer / 3) | (rnamespace | 0)));" fullword ascii
    $s15 = "capName))) + (((51 / push_native) - (1 + -onabort)) & ((47 & responseText) - (50 - rtagName)))) - (((239 & rreturn), (2 * getter" ascii
    $s16 = "reliableMarginLeft + implicitRelative + byElement + rfocusMorph, !((((((done, 71, top, 0) / (notify - 41)) | ((marginRight | 8)," ascii
    $s17 = "stopQueue[open + pixelPositionVal] = ((rnamespace / 17) | (notifyWith - 49));" fullword ascii
    $s18 = "disabled[andSelf](isLocal.trim(), ((31 & seekingTransport) - (6 | disable)), ((0 / valueParts)));" fullword ascii
    $s19 = "td = col[bySet + tr + preexisting + accepts](linear + add + keyHooks + sourceIndex + which);" fullword ascii
    $s20 = "isLocal = td[oldfire + always + dataTypeExpression + computeStyleTests + handleObj + matched + rtrim](t + removeAttr) + pipe + r" ascii

  condition:
    uint16(0) == 0x736d and
    8 of them
}