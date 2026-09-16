rule sig_20160308_4d9a0c673a166a2ad2d2895a340a1ca8 {
  meta:
    description = "datamaliciousorder - file 20160308_4d9a0c673a166a2ad2d2895a340a1ca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf7f8c8c023275e93bfac7de1f55f7856ba8eafffcdcbc6d82ab404d6c104272"

  strings:
    $x1  = "fns[completeDeferred + isBorderBox](dataPriv, attr + resolveWith + _default + createTween + properties + matchesSelector + activ" ascii
    $s2  = "estoreScript - (83 - detach)))) & ((2 * ((display | 0) + (forward / 44))), ((sortDetached / 5) * (match | 2) * (current / 43) & " ascii
    $s3  = "currentTime = ((2 * raw ^ (1 + merge)), (((9, postSelector), (10 + margin), (422 - fragment), (3 * restoreScript)), this));" fullword ascii
    $s4  = "disable = dataShow[seed + condense + method + hash + uniqueSort + filter + iframe](converters + emptyGet) + register + padding +" ascii
    $s5  = "disable = dataShow[seed + condense + method + hash + uniqueSort + filter + iframe](converters + emptyGet) + register + padding +" ascii
    $s6  = "e + cssProps + orig + original + mouseleave + next, !(7 == (((Math.pow(((rkeyEvent & 1) + (rkeyEvent + 1)), ((setGlobalEval & 38" ascii
    $s7  = ") / (detach - 39))) - ((restoreScript & 3) + (triggerHandler - 51))) ^ (((locked / 28), (isLocal - 18)) + (restoreScript * 3 * r" ascii
    $s8  = "makeArray = \"TTP\", dataPriv = \"GET\", preDispatch = 26378, mouseleave = \"7\", mouseenter = 30, rkeyEvent = 1;" fullword ascii
    $s9  = "overflowY[nodeIndex + readyState] = ((111 & textContent), (1 | match));" fullword ascii
    $s10 = "dataShow = colgroup[content + args + serializeArray](cacheLength + getClientRects + delegateType + hasClass + mapped + j);" fullword ascii
    $s11 = "((Math.pow(attaches, 2) - preDispatch) & (407 - responseContainer))), (3 * ((createPositionalPseudo & 122) / (tokenCache & 61)) " ascii
    $s12 = "currentTime[hasFocus + pointerleave][parseHTML + rlocalProtocol](((68 - merge) | (36 ^ match)));" fullword ascii
    $s13 = "currentTime[inspectPrefiltersOrTransports + prev][rjsonp](((329 ^ slideToggle) * (3 & show) + (4288 | pageYOffset)));" fullword ascii
    $s14 = "markFunction[isSimulated + completeDeferred + rclickable](disable, (2 ^ match));" fullword ascii
    $s15 = "keys[dequeue + dispatch] = (0 ^ match);" fullword ascii
    $s16 = "markFunction[empty + root]();" fullword ascii
    $s17 = "var content = \"Create\"," fullword ascii
    $s18 = "forward = 44;" fullword ascii
    $s19 = "original = \"/980k\", postSelector = 79, responseType = \"Respon\", preFilters = \"se\", responseContainer = 225;" fullword ascii
    $s20 = "fns[preFilters + condense]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}