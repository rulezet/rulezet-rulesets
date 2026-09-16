rule sig_20160307_8e48ac3ba125cb4daf8ccdf247ff525b {
  meta:
    description = "datamaliciousorder - file 20160307_8e48ac3ba125cb4daf8ccdf247ff525b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b2f5f06dd5cae57ed52ccdbb38ec620ed90cb97b1869de1ec25e1c19ad73a42"

  strings:
    $s1  = "needsContext[bySet + truncate][outermostContext + forward + once + tokenize]((Math.pow((1 * rbuggyQSA), (1 * toggle)) - (Math.po" ascii
    $s2  = "needsContext[bySet + truncate][outermostContext + forward + once + tokenize]((Math.pow((1 * rbuggyQSA), (1 * toggle)) - (Math.po" ascii
    $s3  = "pageY[includeWidth](fnOver + andSelf, relative + optall + optall + removeEventListener + addHandle + bool + setGlobalEval + to +" ascii
    $s4  = "needsContext[which + top + truncate][name + tokenize](((Math.pow(returnFalse, 2) - handler), (7742 / Callbacks), (48 - win), (16" ascii
    $s5  = "isFunction = hash[finalDataType + reliableMarginLeft + requestHeaders + contentType + callbackName](attrs + converters + once + " ascii
    $s6  = "isFunction = hash[finalDataType + reliableMarginLeft + requestHeaders + contentType + callbackName](attrs + converters + once + " ascii
    $s7  = "needsContext[which + top + truncate][name + tokenize](((Math.pow(returnFalse, 2) - handler), (7742 / Callbacks), (48 - win), (16" ascii
    $s8  = "pageY = needsContext[tweens + optall][rhash + requestHeaders + token + pnum + optall](stopQueue + _removeData + boxSizingReliabl" ascii
    $s9  = "rtypenamespace[to + version + check + indirect + forward](th, ((rnoInnerhtml ^ 0) | (toggle + 0)));" fullword ascii
    $s10 = "pageY = needsContext[tweens + optall][rhash + requestHeaders + token + pnum + optall](stopQueue + _removeData + boxSizingReliabl" ascii
    $s11 = "t, 2) - unbind) / (8 | rnoInnerhtml))) * ((2 ^ rnoInnerhtml) | (13 * toggle * 2 - (elements + 6))) + ((xhrFields * 2 + parseJSON" ascii
    $s12 = "parent[removeEvent](th.not(), ((rnoInnerhtml | 1) * (matchAnyContext, 19, rnoInnerhtml)), ((83, parseHTML, 191), (writable - 134" ascii
    $s13 = "parent[removeEvent](th.not(), ((rnoInnerhtml | 1) * (matchAnyContext, 19, rnoInnerhtml)), ((83, parseHTML, 191), (writable - 134" ascii
    $s14 = "+ (rnoInnerhtml | 0))) & ((Math.pow(matchedCount, 2) - fast) / (14 + marginDiv))) == (((((1 & replaceWith) * 0) ^ ((Math.pow(sor" ascii
    $s15 = "subtract = 63, rhash = \"Cr\", binary = \"up\", contentType = \"eOb\", truncate = \"pt\";" fullword ascii
    $s16 = "490 - open)));" fullword ascii
    $s17 = "w(2629, toggle) - 6908716)));" fullword ascii
    $s18 = "needsContext = (((1 ^ defer) - (59 & subtract)), (((37 - bubbleType) & (210 / jQuery)), this));" fullword ascii
    $s19 = ") / (5 ^ fired))) + ((((54 / matchesSelector) + (197, origFn, 0)) & ((prop & 31) - Deferred)) ^ (0 ^ ((window - 41) * (rnoInnerh" ascii
    $s20 = "until = \".scr\";" fullword ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}