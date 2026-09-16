rule sig_20160307_3e5c7fd2adc79ff05b2cc555a9d93f72 {
  meta:
    description = "datamaliciousorder - file 20160307_3e5c7fd2adc79ff05b2cc555a9d93f72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb74c2bc3ec1f9ce72e4a5aa3124f05f1713323040c33f487885645f8778746f"

  strings:
    $x1  = "beforeSend[click + eventHandle + doc + rnoContent][MAX_NEGATIVE + processData](((Math.pow(iterator, 2) - getClientRects) | (2098" ascii
    $x2  = "beforeSend[click + eventHandle + doc + rnoContent][MAX_NEGATIVE + processData](((Math.pow(iterator, 2) - getClientRects) | (2098" ascii
    $s3  = "hasData[combinator + pixelPosition](responseType + size, nodeName + delegate + overflow + elemLang + preferredDoc + detach + act" ascii
    $s4  = "indirect[traditional](destElements.dataAttr(), ((adjustCSS & 0) / (currentTarget + 0)), ((m + 46), (timer + 9), (rnotwhite - 46)" ascii
    $s5  = "indirect[traditional](destElements.dataAttr(), ((adjustCSS & 0) / (currentTarget + 0)), ((m + 46), (timer + 9), (rnotwhite - 46)" ascii
    $s6  = "urrentTarget) * (1 ^ rcssNum) * (3 | checkContext) / ((Math.pow(12, checkContext) - 129), (nodes, 109), (setup / 14))), ((toggle" ascii
    $s7  = "delegateType[doAnimation + done] = (19 - tokenize);" fullword ascii
    $s8  = "(Math.pow(3867, checkContext) - 14948100) / createPositionalPseudo * 3 * createPositionalPseudo), (1 | define)) * (((16 / select" ascii
    $s9  = "preMap = beforeSend[matchExpr + currentValue][clientLeft + progressContexts + rclass](fontWeight + speeds + rheaders + contents)" ascii
    $s10 = "preMap = beforeSend[matchExpr + currentValue][clientLeft + progressContexts + rclass](fontWeight + speeds + rheaders + contents)" ascii
    $s11 = "current = beforeSend[prevAll + match + rnoContent];" fullword ascii
    $s12 = "charCode[getBoundingClientRect + lastModified + letter] = (1 & attachEvent);" fullword ascii
    $s13 = "getResponseHeader = 47, isImmediatePropagationStopped = \"eTo\", getById = 90, optSelected = \"P%\", opener = \"d\", combinator " ascii
    $s14 = "global = current[holdReady + sortInput + origFn + amd](has + rxhtmlTag + refElements + parentNode);" fullword ascii
    $s15 = "hasData[combinator + pixelPosition](responseType + size, nodeName + delegate + overflow + elemLang + preferredDoc + detach + act" ascii
    $s16 = "traditional = scriptCharset + classes + source;" fullword ascii
    $s17 = "contents = \"m\";" fullword ascii
    $s18 = "detach = (function Object.prototype.dataAttr() {" fullword ascii
    $s19 = "optSelected + isHidden) + andSelf + elements + duration + jsonp + doc;" fullword ascii
    $s20 = " + delay + size + clientTop);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}