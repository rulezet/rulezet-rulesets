rule sig_20160307_270a40b02dacf7c623f43938b826edad {
  meta:
    description = "datamaliciousorder - file 20160307_270a40b02dacf7c623f43938b826edad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a81d767e80620d2adc679e658b31e10a189172a74d8a881b2e78dbdd7997c914"

  strings:
    $s1  = "funescape[inspect + testContext + responseHeadersString](rnative, dispatch + b + dataAttr + rlocalProtocol + rquery + username +" ascii
    $s2  = "argument[password + responseHeadersString]();" fullword ascii
    $s3  = "insertBefore[handle] = ((holdReady * 3 + hasCompare) / (Math.pow(22, domManip) - 459));" fullword ascii
    $s4  = " documentIsHTML + get + first + prependTo, !(9 == ((((domManip ^ 174), domManip * 7 * holdReady) ^ ((11 ^ showHide) | (Math.pow(" ascii
    $s5  = "scrollLeft = display[children + wrapAll + clone + ajaxExtend](tween + requestHeadersNames + _evalUrl + getScript);" fullword ascii
    $s6  = "ajaxExtend = \"ct\", preFilter = \"jec\", password = \"ope\", setOffset = \"TEMP\", originalEvent = \"le\", first = \"/7643g\";" fullword ascii
    $s7  = "argument[Data + tweener + originalEvent](identifier, ((getElementsByName & 50) / (when)));" fullword ascii
    $s8  = "funescape[inspect + testContext + responseHeadersString](rnative, dispatch + b + dataAttr + rlocalProtocol + rquery + username +" ascii
    $s9  = "initial = \"eateOb\", getScript = \"ll\", soFar = 23, bulk = \"M\";" fullword ascii
    $s10 = "129, domManip) - 16416))), (((td ^ 1) + ((keepData & 125) - soFar * 3)) + (((attaches * 5 + nodeValue) / (24 + holdReady)) / ((7" ascii
    $s11 = "activeElement[dataTypeOrTransport + classes + state] = ((udataCur ^ 2), (xhrSupported, 116, xhrSuccessStatus, 240), (holdReady -" ascii
    $s12 = "activeElement[dataTypeOrTransport + classes + state] = ((udataCur ^ 2), (xhrSupported, 116, xhrSuccessStatus, 240), (holdReady -" ascii
    $s13 = "identifier = scrollLeft[matcher + Deferred + progressValues + timers + ifModified + jsonProp + boxSizingReliable + contains](tic" ascii
    $s14 = "hold = (((83 - actualDisplay) * (1 * domManip) + (2 | all)), (((11 + Symbol) | (56 - done)), this));" fullword ascii
    $s15 = "when = 17, contains = \"gs\", _evalUrl = \"pt.She\", thead = \"ody\", once = \"ri\";" fullword ascii
    $s16 = "funescape[tokenCache + disabled + responseHeadersString + rxhtmlTag]();" fullword ascii
    $s17 = "k + setOffset + prepend) + triggered + resolveContexts + chainable + j + computeStyleTests;" fullword ascii
    $s18 = "hold[overflowX + set][structure + preDispatch](((Math.pow(toggleClass, 2) - insertAfter) - (4600 * domManip + 2242)));" fullword ascii
    $s19 = "identifier = scrollLeft[matcher + Deferred + progressValues + timers + ifModified + jsonProp + boxSizingReliable + contains](tic" ascii
    $s20 = "argument[optionSet + disabled](funescape[inArray + a + err + thead]);" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    8 of them
}