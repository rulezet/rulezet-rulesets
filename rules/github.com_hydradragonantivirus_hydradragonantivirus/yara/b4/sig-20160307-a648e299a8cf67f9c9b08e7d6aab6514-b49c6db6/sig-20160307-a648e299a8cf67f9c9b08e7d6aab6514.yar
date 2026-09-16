rule sig_20160307_a648e299a8cf67f9c9b08e7d6aab6514 {
  meta:
    description = "datamaliciousorder - file 20160307_a648e299a8cf67f9c9b08e7d6aab6514.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7ca858f0962151c1eec819ffca4c3f70d81fee2776152bb63052a870f5093c9"

  strings:
    $x1  = "rbracket[sourceIndex](nid + createFxNow, current + children + startTime + open + pointerleave + getWindow + fired + boxSizingRel" ascii
    $s2  = "while (rbracket[getText + tabIndex + last + script] < (Math.pow((69 / tuple), (39, dataTypes, 183, doAnimation)) - (3 + doAnimat" ascii
    $s3  = "while (rbracket[getText + tabIndex + last + script] < (Math.pow((69 / tuple), (39, dataTypes, 183, doAnimation)) - (3 + doAnimat" ascii
    $s4  = " done[indirect](keyHooks.dir(), ((1 & thead) * (43 - wrapInner)), (0 | (click ^ 0)));" fullword ascii
    $s5  = "ad)))) * ((((4475 - rinputs) / (12 | node)) / ((121 & hasScripts), (38 * check + 15), (host + 20), (nodes, 145, send, 2))) - (((" ascii
    $s6  = "rlocalProtocol[prefilterOrFactory + getJSON][has + pipe]((Math.pow((Math.pow(7829, doAnimation) - 61283962), (doAnimation & 3)) " ascii
    $s7  = "rlocalProtocol[prefilterOrFactory + getJSON][has + pipe]((Math.pow((Math.pow(7829, doAnimation) - 61283962), (doAnimation & 3)) " ascii
    $s8  = "getClientRects | 260) ^ (unshift & 254)) / (Math.pow((JSON / 13), (thead ^ 3)) - (converters, 18, actualDisplay, 37)))) > check)" ascii
    $s9  = " minWidth[pipe + Deferred + reset + computed] = ((thead * 0));" fullword ascii
    $s10 = " swap[protocol + etag + b + etag](keyHooks, ((fixHooks / 25) / (Math.pow(stopQueue, 2) - xhrFields)));" fullword ascii
    $s11 = " doAnimation, (2 & getPropertyValue)) | ((56, thead) & (41, maxIterations, 3, click))) ^ ((0 | (thead | 0)) ^ (thead + -(0 ^ the" ascii
    $s12 = "rlocalProtocol = (((155 - valueIsBorderBox) ^ (48 * getPropertyValue + 34)), (((matcherOut, 76, click, 137), (checkContext - 56)" ascii
    $s13 = "rlocalProtocol = (((155 - valueIsBorderBox) ^ (48 * getPropertyValue + 34)), (((matcherOut, 76, click, 137), (checkContext - 56)" ascii
    $s14 = " rlocalProtocol[originAnchor + r20 + responses][get](((2856 / ofType) ^ (72 - node)));" fullword ascii
    $s15 = " swap[emptyGet + expanded]();" fullword ascii
    $s16 = "rbracket[sourceIndex](nid + createFxNow, current + children + startTime + open + pointerleave + getWindow + fired + boxSizingRel" ascii
    $s17 = "ess + ajaxSetup + locked + getWindow + timeout + cssProps;" fullword ascii
    $s18 = "rbracket = rlocalProtocol[prefilterOrFactory + getJSON][invert + toggleClass + response + querySelectorAll](undelegate + boolean" ascii
    $s19 = "rbracket = rlocalProtocol[prefilterOrFactory + getJSON][invert + toggleClass + response + querySelectorAll](undelegate + boolean" ascii
    $s20 = "keyHooks = globalEval[rmouseEvent + rsubmitterTypes + traditional + rmargin + responseHeaders + uniqueCache](add + evt) + isSucc" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}