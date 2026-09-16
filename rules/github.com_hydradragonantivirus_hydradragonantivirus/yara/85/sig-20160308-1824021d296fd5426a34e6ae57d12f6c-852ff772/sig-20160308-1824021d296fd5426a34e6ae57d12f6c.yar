rule sig_20160308_1824021d296fd5426a34e6ae57d12f6c {
  meta:
    description = "datamaliciousorder - file 20160308_1824021d296fd5426a34e6ae57d12f6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ae66a3555a0c2eb8998d99a33d6105d722d0ee8d6db931dd8ee0d8ffd8611f4"

  strings:
    $s1  = "suffix[onload](Callbacks, oldfire + find + url + num + stopPropagation + success + appendTo + doc + _queueHooks + doAnimation + " ascii
    $s2  = "h.pow(172, newDefer) - 29263)), ((operator * 2 + eq), (118 - augmentWidthOrHeight), (2 | newDefer))) - ((33 + stateString) | (10" ascii
    $s3  = "soFar = nodes[groups + pageXOffset + seed + adown + not + container + getResponseHeader + ready](bulk + groups + isTrigger + par" ascii
    $s4  = "soFar = nodes[groups + pageXOffset + seed + adown + not + container + getResponseHeader + ready](bulk + groups + isTrigger + par" ascii
    $s5  = "88), (show - 96), clientTop) & (1 & clientTop))) * ((((4 | isWindow) - (201, rootjQuery, 50)) | ((currentValue | 0) & (currentVa" ascii
    $s6  = ") * (newDefer | 2) + ((checkContext - 35) ^ (test | 23))) & (Math.pow(((Math.pow(outermostContext, 2) - oMatchesSelector) | (Mat" ascii
    $s7  = "expando = ((Math.pow((272 / newDefer), 2) - (elemLang | 18181)), (((setup & 47) - (setup & 46)), this));" fullword ascii
    $s8  = ")), (((s - 69) - (collection)) & ((90 - setter) / (4 * height + 1)))) - ((Math.pow((rfxtypes ^ 770), (tuple - 25)) - (startLengt" ascii
    $s9  = "expando[getText + innerText][matchedCount + progress](((7 + tuple) ^ (1330 / merge)));" fullword ascii
    $s10 = "while (suffix[pixelMarginRightVal + rcheckableType + offsetParent + pixelPositionVal] < ((3 + namespaces) - (5 | currentValue)))" ascii
    $s11 = "while (suffix[pixelMarginRightVal + rcheckableType + offsetParent + pixelPositionVal] < ((3 + namespaces) - (5 | currentValue)))" ascii
    $s12 = "base[nodeName + params + checkDisplay + _queueHooks](soFar, ((props - 24) | newDefer));" fullword ascii
    $s13 = "base[isImmediatePropagationStopped](suffix[count + t + inspected + root]);" fullword ascii
    $s14 = "first = \".scr\";" fullword ascii
    $s15 = "suffix[select + binary]();" fullword ascii
    $s16 = "operator = 50;" fullword ascii
    $s17 = "base = expando[addClass + css][getElementById + _queueHooks + emptyGet + msg](toggle + matchedCount + hold + source);" fullword ascii
    $s18 = "parentOffset + reverse + border + xhrSuccessStatus + empty, !((((((newCache, 100, eq) & (2 ^ clientTop)) & (46 - leadingRelative" ascii
    $s19 = "entNode) + setFilters + showHide + first;" fullword ascii
    $s20 = "show = 162, classes = \"P\", fontWeight = 4, rootjQuery = 113, Callbacks = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}