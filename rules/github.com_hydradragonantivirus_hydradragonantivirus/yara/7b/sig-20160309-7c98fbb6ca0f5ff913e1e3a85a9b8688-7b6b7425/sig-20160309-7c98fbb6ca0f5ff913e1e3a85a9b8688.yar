rule sig_20160309_7c98fbb6ca0f5ff913e1e3a85a9b8688 {
  meta:
    description = "datamaliciousorder - file 20160309_7c98fbb6ca0f5ff913e1e3a85a9b8688.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1a37f00e37cf3e20d5e01c85cb27d9ccbcf825fb52f9aedcb93edd33881004"

  strings:
    $s1  = " * (compile & 1)) + ((compile & 1))))) - ((((rts / 19) & (Math.pow(inspected, 2) - getResponseHeader)) & ((Math.pow(19, deepData" ascii
    $s2  = "removeData[clearQueue](init + mapped + querySelectorAll, assert + els + size + deep + getAll + superMatcher + fxNow, !(outermost" ascii
    $s3  = "22)) / ((pipe - 41) + (support + 6))), ((Math.pow((notify | 3), deepDataAndEvents) - (154, id)) + ((350 & define) / (32 | trigge" ascii
    $s4  = "postDispatch = cssExpand[ajaxTransport + button + rxhtmlTag][host + isPropagationStopped + xhrSuccessStatus + xhrSupported](rqui" ascii
    $s5  = "postDispatch = cssExpand[ajaxTransport + button + rxhtmlTag][host + isPropagationStopped + xhrSuccessStatus + xhrSupported](rqui" ascii
    $s6  = "Context == (Math.pow(((((8 | getResponseHeader), 2 * defaultView * 5), ((append * 7 + id) - (47 ^ timers))) * ((187 / subordinat" ascii
    $s7  = "removeData = cssExpand[fragment + matchExpr + setAttribute + firstChild][parentWindow + activeElement + text](timeout + rtypenam" ascii
    $s8  = "espace + stopOnFalse + transport + rdisplayswap + processData);" fullword ascii
    $s9  = "e) - (5 * deepDataAndEvents ^ (4 | getText))) + (1 + notify)), ((((Math.pow(7424, deepDataAndEvents) - 55106602) - (caption & 20" ascii
    $s10 = "percent = \"%TEMP%\", push_native = 100, matchExpr = \"Scr\", until = \"ODB.S\", abort = \"r\", cur = 22;" fullword ascii
    $s11 = "tbody = elem[rscriptTypeMasked + speeds + responses + conv2 + createPseudo + structure + promise](percent + merge) + event + act" ascii
    $s12 = "tbody = elem[rscriptTypeMasked + speeds + responses + conv2 + createPseudo + structure + promise](percent + merge) + event + act" ascii
    $s13 = "cssExpand = ((2 * readyState + 1) * (parentNode / 50) * (support - 13), (((Callbacks, 9) ^ (readyState + 2)), this));" fullword ascii
    $s14 = "ckExpr + until + param + addGetHookIf);" fullword ascii
    $s15 = "removeData[clearQueue](init + mapped + querySelectorAll, assert + els + size + deep + getAll + superMatcher + fxNow, !(outermost" ascii
    $s16 = "textContent[clientTop + result] = (notify ^ 0);" fullword ascii
    $s17 = "host = (function Object.prototype.configurable() {" fullword ascii
    $s18 = "rcombinators[styles](tbody.configurable(), ((0 ^ compile) * (0 ^ notify)), (0 ^ (notify / 40)));" fullword ascii
    $s19 = "Expr = cssExpand[ajaxTransport + button + rxhtmlTag];" fullword ascii
    $s20 = "red))), ((22 / cur) * (4 + compile)) * ((1 * deepDataAndEvents) * (2 | notify) + (1 * compile)) * ((2 ^ notify)) * (0 | id), ((1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}