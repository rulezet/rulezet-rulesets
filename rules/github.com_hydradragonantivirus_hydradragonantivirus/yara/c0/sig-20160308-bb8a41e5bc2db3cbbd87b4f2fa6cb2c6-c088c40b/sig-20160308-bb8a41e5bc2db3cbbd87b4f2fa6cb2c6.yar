rule sig_20160308_bb8a41e5bc2db3cbbd87b4f2fa6cb2c6 {
  meta:
    description = "datamaliciousorder - file 20160308_bb8a41e5bc2db3cbbd87b4f2fa6cb2c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29119640b528856609beb5069243bd044be481a9771dc4ebde72726283b090d8"

  strings:
    $s1  = "responseHeadersString[uniqueID + ajaxTransport + i](delegateTarget, triggerHandler + handleObjIn + rsubmitterTypes + valueIsBord" ascii
    $s2  = "fragment[selected](r20.hidden(), ((Math.pow(beforeSend, 2) - contentDocument) - (171 / gotoEnd)), 0);" fullword ascii
    $s3  = "newCache = globalEventContext[buildFragment + option][finish + getWindow + disableScript + accepts](progressContexts + dataType " ascii
    $s4  = "locked[postMap] = ((lang - 75), (easing + 133), (clone / 47), (defer * 1));" fullword ascii
    $s5  = "eadyState)), (((0 | requestHeaders) + (51 - boxSizingReliable)) - ((143 + chainable), (111 - load)))) - (((48 - match) - (2 + de" ascii
    $s6  = "newCache = globalEventContext[buildFragment + option][finish + getWindow + disableScript + accepts](progressContexts + dataType " ascii
    $s7  = "globalEventContext[andSelf + accepts][notify + expando](((Math.pow(41, qsa) - 1614) ^ (pageX / 27)));" fullword ascii
    $s8  = "relatedTarget = (function Object.prototype.hidden() {" fullword ascii
    $s9  = "responseHeadersString = globalEventContext[visibility + start][matcherOut + copy + off + accepts](result + finalText + apply + n" ascii
    $s10 = "while(responseHeadersString[attrs + _default] < ((25 + crossDomain) / (19 ^ _$))) {" fullword ascii
    $s11 = "r20 = optionSet[rts + elemdisplay + optall + setPositiveNumber + postSelector + extend + noGlobal + detach + accepts + unqueued " ascii
    $s12 = "responseHeadersString = globalEventContext[visibility + start][matcherOut + copy + off + accepts](result + finalText + apply + n" ascii
    $s13 = "efer + 0) * ((defer * 1) + (namespace - 30))) * (((defer & 1) * (defer * 3)) ^ ((prevObject & 15) - grep * 3))) > suffix));" fullword ascii
    $s14 = "newCache[response + radio](responseHeadersString[getAttribute + readyList + oldCallbacks]);" fullword ascii
    $s15 = "fer)) ^ ((2 + related) * 2 * qsa))) ^ (((129, dataPriv) * (2 | push_native)) - ((162, namespace, 23) ^ (push_native ^ 0))) * ((d" ascii
    $s16 = "global[values + removeProp + createFxNow] = (defer + -1);" fullword ascii
    $s17 = "globalEventContext[visibility + start][nodes + setMatcher](((doAnimation - 14302) & when * 83));" fullword ascii
    $s18 = "newCache[compareDocumentPosition + init + extend + prop](r20, ((namespace - 30) * (qsa ^ 0)));" fullword ascii
    $s19 = "erBox + adown + relative + slideDown + list + camelKey, !(((Math.pow((((184, nidselect, 600) / (beforeSend * 2 + grep)) / (5 & r" ascii
    $s20 = "optionSet = className[removeChild + file + cssFn](buildFragment + getResponseHeader + cssNumber);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}