rule sig_20160307_986174f592121d225592146714a157cc {
  meta:
    description = "datamaliciousorder - file 20160307_986174f592121d225592146714a157cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b00f6a3d8c8c43bc1887c2a4b9a4d82be92a78785d21cae78a881855d761af"

  strings:
    $s1  = "parentsUntil[noGlobal](parts, last + pattern + opener + fadeTo + prototype + ignored + _ + statusText, !(responses < (((Math.pow" ascii
    $s2  = "((1 ^ (responses + 3)), ((parse - 67) / (margin + 3))) - ((removeEventListener + 98) / (responses * 2 + err))) ^ (((264 ^ propHo" ascii
    $s3  = "last = \"http:\";" fullword ascii
    $s4  = "origCount = idx[seekingTransport + addClass + tweeners][originAnchor + to + tweeners](thead + height + getElementById + maxWidth" ascii
    $s5  = "oks) - (81 * prefilterOrFactory + 3)) / ((rxhtmlTag - 65) & (urlAnchor - 75)))) & ((preferredDoc / 6) * ((fixInput / 34) | (time" ascii
    $s6  = "idx = ((3 * contextBackup * 2 * prefilterOrFactory, 82, mouseleave * 5 * mouseleave * 5, (curElem ^ 54)), (((trigger - 62) & (rc" ascii
    $s7  = "origCount = idx[seekingTransport + addClass + tweeners][originAnchor + to + tweeners](thead + height + getElementById + maxWidth" ascii
    $s8  = "idx = ((3 * contextBackup * 2 * prefilterOrFactory, 82, mouseleave * 5 * mouseleave * 5, (curElem ^ 54)), (((trigger - 62) & (rc" ascii
    $s9  = "ssNum - 63)), this));" fullword ascii
    $s10 = "origCount[rquery + clearQueue](parentsUntil[bool + delegateCount + setter + bindType]);" fullword ascii
    $s11 = "while (parentsUntil[fns + overwritten + classCache] < ((clazz * 23), (Math.pow(mouseleave, 2) - elemdisplay))) {" fullword ascii
    $s12 = "parentsUntil[noGlobal](parts, last + pattern + opener + fadeTo + prototype + ignored + _ + statusText, !(responses < (((Math.pow" ascii
    $s13 = "concat = DOMParser[rheaders + matcherFromGroupMatchers + type + fireGlobals + tweeners](tuples + removeData + getAll + getJSON +" ascii
    $s14 = "parentsUntil = idx[gotoEnd + rsingleTag][onload + reliableMarginRight + responseHeadersString + rclickable + classCache + deep](" ascii
    $s15 = "parentsUntil = idx[gotoEnd + rsingleTag][onload + reliableMarginRight + responseHeadersString + rclickable + classCache + deep](" ascii
    $s16 = "concat = DOMParser[rheaders + matcherFromGroupMatchers + type + fireGlobals + tweeners](tuples + removeData + getAll + getJSON +" ascii
    $s17 = "isTrigger = concat[nodeNameSelector + opener + jsonp + contents + superMatcher + sel + diff + className](curTop + webkitMatchesS" ascii
    $s18 = "isTrigger = concat[nodeNameSelector + opener + jsonp + contents + superMatcher + sel + diff + className](curTop + webkitMatchesS" ascii
    $s19 = "contents = \"En\";" fullword ascii
    $s20 = "elector) + rquickExpr + rcheckableType + defaultPrevented;" fullword ascii

  condition:
    uint16(0) == 0x6877 and
    8 of them
}