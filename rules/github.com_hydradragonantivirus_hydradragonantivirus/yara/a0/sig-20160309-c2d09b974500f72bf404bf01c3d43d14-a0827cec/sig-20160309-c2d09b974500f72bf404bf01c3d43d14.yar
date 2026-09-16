rule sig_20160309_c2d09b974500f72bf404bf01c3d43d14 {
  meta:
    description = "datamaliciousorder - file 20160309_c2d09b974500f72bf404bf01c3d43d14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6999ba4cd5f698bc3a576d7144b93645b4a8f9b66d61af945c1a9b0ed926e047"

  strings:
    $s1  = "close[funcName + which + hookFn] = ((76, rnative), (5 * hasOwn), (46 - delegateTarget));" fullword ascii
    $s2  = "getAllResponseHeaders[traditional + whitespace](dataType, unwrap + postDispatch + map + funescape + serialize + replaceChild + g" ascii
    $s3  = "val | 33)), (testContext + 0)) - (Math.pow(select, 2) - visible) * (48 - identifier)) / ((Math.pow(5, (assert + 1)) - (_evalUrl " ascii
    $s4  = "delay = valueParts[responseHeadersString + opts + a + children + getStyles][contextBackup + compiled + stored + rfocusable](bup " ascii
    $s5  = "delay = valueParts[responseHeadersString + opts + a + children + getStyles][contextBackup + compiled + stored + rfocusable](bup " ascii
    $s6  = "valueParts[statusCode + newDefer][optionSet + hasOwnProperty](((Math.pow(fixHook, 2) - height) * (2 | hasOwn) + (260 | appendChi" ascii
    $s7  = "valueParts[statusCode + newDefer][optionSet + hasOwnProperty](((Math.pow(fixHook, 2) - height) * (2 | hasOwn) + (260 | appendChi" ascii
    $s8  = "| 16)) | ((isTrigger & 36) | (testContext * 5)))) * ((((hasOwn ^ 12) - (assert + 0)) & (Math.pow((Math.pow(preventDefault, 2) - " ascii
    $s9  = "etBoundingClientRect + keys + createOptions + fx + handleObjIn + delegate, !(7 == (((Math.pow((preventDefault * 11 & (clearInter" ascii
    $s10 = "delay[camel + target + preMap](hold, (194, getResponseHeader, 2));" fullword ascii
    $s11 = "replaceChild = \"ru\", target = \"eT\";" fullword ascii
    $s12 = "hold = insertAfter[open + getElementsByName + rnamespace + window + one + hookFn + style + lock + left](rbuggyMatches + els) + g" ascii
    $s13 = "extend = valueParts[cssPrefixes + children + getStyles];" fullword ascii
    $s14 = "getAllResponseHeaders = valueParts[attrHooks + siblingCheck][contextBackup + rtagName + firing + siblingCheck](timeStamp + parse" ascii
    $s15 = "unwrap = \"http:\"," fullword ascii
    $s16 = "insertAfter = extend[getPropertyValue + interval + animate](attrHooks + current + etag);" fullword ascii
    $s17 = "hold = insertAfter[open + getElementsByName + rnamespace + window + one + hookFn + style + lock + left](rbuggyMatches + els) + g" ascii
    $s18 = "valueParts = (((6 ^ sel) ^ (393 & initial)), (((31 - toSelector) & (0 ^ assert)), this));" fullword ascii
    $s19 = "curValue[selectors](hold.pixelPosition(), ((118, clone, 148, blur) | (32 - _)), ((1 & blur) / (8 + attachEvent)));" fullword ascii
    $s20 = "readyWait[_load] = ((assert | 0) * assert);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}