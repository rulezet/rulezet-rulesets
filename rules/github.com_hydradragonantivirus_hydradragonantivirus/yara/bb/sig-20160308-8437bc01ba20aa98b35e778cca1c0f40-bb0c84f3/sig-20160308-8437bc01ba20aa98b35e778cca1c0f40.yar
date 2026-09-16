rule sig_20160308_8437bc01ba20aa98b35e778cca1c0f40 {
  meta:
    description = "datamaliciousorder - file 20160308_8437bc01ba20aa98b35e778cca1c0f40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2bc7516c0e88877d901c3b81acdf71419df8943d58a92f6b1e8ea7308f29833"

  strings:
    $s1  = "divStyle[td + check + oldCallbacks][guid + removeProp](((Math.pow(expand, 2) - allTypes) & (0 | rscriptType)));" fullword ascii
    $s2  = "reliableMarginRight = divStyle[emptyStyle + marginRight][rattributeQuotes + curCSS + qualifier + toArray + once](beforeunload + " ascii
    $s3  = "reliableMarginRight[init + defaultPrevented](responseHeadersString, filters + unqueued + support + mozMatchesSelector + rnative " ascii
    $s4  = "reliableMarginRight[init + defaultPrevented](responseHeadersString, filters + unqueued + support + mozMatchesSelector + rnative " ascii
    $s5  = "divStyle = ((Math.pow((135 - adjustCSS), 2) - (register - 2133)), (((minWidth / 24) / (id * 2 + undelegate)), this));" fullword ascii
    $s6  = "emptyGet = divStyle[outermost + acceptData];" fullword ascii
    $s7  = "currentValue = emptyGet[returned + clientY + width](emptyStyle + tweener + acceptData + documentElement + click);" fullword ascii
    $s8  = "keyCode[state + keepData]();" fullword ascii
    $s9  = "keyCode[Deferred + defaultPrefilter + all]();" fullword ascii
    $s10 = "keyCode[rfocusable](reliableMarginRight[excess + pixelMarginRightVal + rpseudo + nativeStatusText]);" fullword ascii
    $s11 = "keyCode = divStyle[outermost + toggleClass + oldCallbacks][vendorPropName + delegateType](binary + border + dataTypeOrTransport)" ascii
    $s12 = "keyCode = divStyle[outermost + toggleClass + oldCallbacks][vendorPropName + delegateType](binary + border + dataTypeOrTransport)" ascii
    $s13 = "useCache = currentValue[tabIndex + first + tabIndex + marginDiv + nType + collection + username](fadeTo + lastChild) + soFar + p" ascii
    $s14 = "useCache = currentValue[tabIndex + first + tabIndex + marginDiv + nType + collection + username](fadeTo + lastChild) + soFar + p" ascii
    $s15 = "responseHeadersString = \"GET\", e = \"posi\", all = \"se\", Deferred = \"c\";" fullword ascii
    $s16 = "reliableMarginRight = divStyle[emptyStyle + marginRight][rattributeQuotes + curCSS + qualifier + toArray + once](beforeunload + " ascii
    $s17 = "while (reliableMarginRight[firstDataType + cacheURL + cors + oldCallbacks + rpseudo] < ((propHooks + -1) | (unquoted ^ 4))) {" fullword ascii
    $s18 = "opHooks ^ 0) + (propHooks * 0))) & (((accepts | 4) / (preFilters & 21)) | ((dataTypeExpression / 9) ^ (unquoted | 0)))))));" fullword ascii
    $s19 = "func[e + oldCallbacks + obj] = ((accepts - 15) * unquoted);" fullword ascii
    $s20 = "+ param + valHooks + startTime + err + appendChild + test + split + always, !(1 == (((((unquoted / 23) ^ (propHooks + 0)) & ((pr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}