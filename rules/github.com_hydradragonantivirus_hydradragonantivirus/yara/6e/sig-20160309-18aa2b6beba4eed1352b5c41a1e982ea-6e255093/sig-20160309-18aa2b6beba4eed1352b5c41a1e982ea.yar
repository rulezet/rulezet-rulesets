rule sig_20160309_18aa2b6beba4eed1352b5c41a1e982ea {
  meta:
    description = "datamaliciousorder - file 20160309_18aa2b6beba4eed1352b5c41a1e982ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30d5e2d5af3b4676ccfa9334cfebdfe670d5cffa9deef50585fcaa62ba2f372e"

  strings:
    $s1  = "init = inspected[preferredDoc + _ + what + copy + colgroup + attachEvent + hash](sortDetached + rxhtmlTag) + setOffset + targets" ascii
    $s2  = "init = inspected[preferredDoc + _ + what + copy + colgroup + attachEvent + hash](sortDetached + rxhtmlTag) + setOffset + targets" ascii
    $s3  = "bySet[nonce](url, statusCode + elem + dataFilter + getElementsByClassName + fromCharCode + parseOnly + conv2 + rjsonp + traditio" ascii
    $s4  = "dir = (((10 * isPropagationStopped) * (1 + tick) + 2 * isPropagationStopped * 2), (((Math.pow(replaceAll, 2) - isNumeric) & (58," ascii
    $s5  = "dir = (((10 * isPropagationStopped) * (1 + tick) + 2 * isPropagationStopped * 2), (((Math.pow(replaceAll, 2) - isNumeric) & (58," ascii
    $s6  = "bySet = dir[disabled + letterSpacing + valueIsBorderBox][truncate + Symbol + map](rfxtypes + lastChild + postSelector);" fullword ascii
    $s7  = "nal, !(((((2 * maxWidth - 2 * pseudo) / ((0 | attr) & 31)) - ((tick + -1) ^ (tick))) * ((((193 | promise), 59, (e, 36, stateStri" ascii
    $s8  = "prependTo = dir[responseContainer + valueIsBorderBox][stateVal + last](createFxNow + interval + rmouseEvent + keyHooks + subtrac" ascii
    $s9  = "prependTo = dir[responseContainer + valueIsBorderBox][stateVal + last](createFxNow + interval + rmouseEvent + keyHooks + subtrac" ascii
    $s10 = "ng, 1)) ^ promise) ^ (((0 / removeEvent) / (7 * requestHeadersNames + 1)) | ((calculatePosition / 14) * (conv ^ 1))))) == (((emp" ascii
    $s11 = "bySet[nonce](url, statusCode + elem + dataFilter + getElementsByClassName + fromCharCode + parseOnly + conv2 + rjsonp + traditio" ascii
    $s12 = "prependTo[setFilters + currentValue + relative](optall);" fullword ascii
    $s13 = "prependTo[writable + winnow + rparentsprev](init, (1 + (conv | 1)));" fullword ascii
    $s14 = "optall = bySet[unquoted + fixHooks + hold];" fullword ascii
    $s15 = "closest[rreturn + relative]();" fullword ascii
    $s16 = "finish = \"Run\"," fullword ascii
    $s17 = " addEventListener)), this));" fullword ascii
    $s18 = "_default = 46, hash = \"gs\";" fullword ascii
    $s19 = "getElementsByClassName = \"no\", promise = 3, parseOnly = \"x.\";" fullword ascii
    $s20 = "pseudo = 17;" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}