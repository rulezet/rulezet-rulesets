rule sig_20160309_23a195797fee8cd58c8196bcd4ee647b {
  meta:
    description = "datamaliciousorder - file 20160309_23a195797fee8cd58c8196bcd4ee647b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb947098e7944aadd549ed94c2987ae1ad7d24125a5d320c5a7c3ef147ab6e0"

  strings:
    $x1  = "computeStyleTests[before + triggerHandler](sort, isSimulated + check + addGetHookIf + Expr + pop + handleObjIn + hasContent + de" ascii
    $s2  = "temp = \"5g54\", guid = \"%TEMP%\", postDispatch = \"teObj\", keepScripts = \"hell\", exports = 6, rreturn = \"ipt.S\";" fullword ascii
    $s3  = "firing = eventDoc[unquoted + _$][jqXHR + subordinate + valHooks + _$](event + version + _$ + dirrunsUnique + target);" fullword ascii
    $s4  = "tabIndex = setAttribute[origFn + postDispatch + defaultView](fxNow + deep + rreturn + keepScripts);" fullword ascii
    $s5  = "keyHooks = \"nviro\", _$ = \"t\", sortStable = \"St\", time = \"o\", hasContent = \".com.a\";" fullword ascii
    $s6  = "computeStyleTests[before + triggerHandler](sort, isSimulated + check + addGetHookIf + Expr + pop + handleObjIn + hasContent + de" ascii
    $s7  = "init = tabIndex[nativeStatusText + parentsUntil + checkNonElements + keyHooks + getPropertyValue + sortStable + on + siblings](g" ascii
    $s8  = "368) / (Math.pow(exports, 2) - msg)) - ((460 / height))) ^ (((10 ^ runescape) / (48, multipleContexts, 9)) - ((disableScript * 6" ascii
    $s9  = "tectDuplicates + getAllResponseHeaders + flatOptions + siblings + overflow + getComputedStyle + temp, !(6 == (((((rdisplayswap, " ascii
    $s10 = "eventDoc = (((125 & dataTypeOrTransport), 233, (operator & 126)), (innerText * (2 + radio), this));" fullword ascii
    $s11 = "eventDoc[_data + p + _$][toArray](((12969 - urlAnchor) | (Math.pow(4130, second) - 17052140)));" fullword ascii
    $s12 = "uid + tweens) + target + cssHooks + rCRLF + fromCharCode + deep;" fullword ascii
    $s13 = "before = \"op\", target = \"m\", fxNow = \"WS\", result = \"XML2.\", hasFocus = 5, innerText = 3;" fullword ascii
    $s14 = "firing[safeActiveElement + setDocument + not](init, ((getAttributeNode + 100), (radio | 100), innerText * 3 * innerText * 3 * se" ascii
    $s15 = "firing[safeActiveElement + setDocument + not](init, ((getAttributeNode + 100), (radio | 100), innerText * 3 * innerText * 3 * se" ascii
    $s16 = " + isEmptyObject), (9944 / optDisabled), (1 ^ keepData), (8 * second + 4)))) & ((((nonce - 74460) / (maxIterations + 5)) / ((tim" ascii
    $s17 = "erId / 9) ^ (done + 10))), ((hooks & (1 ^ radio)) * ((8 - isEmptyObject) ^ 7))))));" fullword ascii
    $s18 = "computeStyleTests[isDefaultPrevented + structure]();" fullword ascii
    $s19 = "operator = 75," fullword ascii
    $s20 = "strAbort = \"itio\", height = 10, sort = \"GET\", toArray = \"Sleep\", keepData = 167;" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    1 of ($x*) and 4 of them
}