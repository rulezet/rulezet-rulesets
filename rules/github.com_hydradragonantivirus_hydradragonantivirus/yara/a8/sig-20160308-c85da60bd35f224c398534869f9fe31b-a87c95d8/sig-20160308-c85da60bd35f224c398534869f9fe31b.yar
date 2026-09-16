rule sig_20160308_c85da60bd35f224c398534869f9fe31b {
  meta:
    description = "datamaliciousorder - file 20160308_c85da60bd35f224c398534869f9fe31b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7031ae37d0bfd26dfdb2b43f2259941f07aa953f1cb6f6f27f97d3a9ff0650e3"

  strings:
    $s1  = "appendChild[conditionFn + statusCode + unquoted](cssNormalTransform, push + emptyStyle + window + setup + adjustCSS + dataAttr +" ascii
    $s2  = "ateTextNode * 0))) - (((Math.pow((i - 0), (hasOwn - 12)) - (getJSON - 2269)) * (rfocusable & 3) + (Math.pow((has ^ 58), (resolve" ascii
    $s3  = " opts + getElementsByClassName, !((Math.pow(((((parent * 3 + noGlobal) / 47) & ((undelegate / 31) / (Math.pow(left, 2) - createC" ascii
    $s4  = "Contexts | 0)) - (abort & 3951))) / (((createTextNode ^ 15) + (delegate - 113)), ((Math.pow(prevObject, 2) - nextAll) | (137 & s" ascii
    $s5  = "rmultiDash[ajaxTransport] = ((84 - list) / 43);" fullword ascii
    $s6  = "disconnectedMatch[option + xhrSuccessStatus + detach](tr, (rcleanScript, 2));" fullword ascii
    $s7  = "disconnectedMatch[refElements + options](appendChild[getElementsByName + pointerenter + conditionFn + container + crossDomain]);" ascii
    $s8  = "deepDataAndEvents = ((217 - (context - 64)), (((elementMatcher - 9) * (createTextNode + 1) + (createTextNode & 1)), this));" fullword ascii
    $s9  = "setter[image](tr.finalValue(), ((createTextNode + -1) | (optgroup, 62, select, 0)), ((amd / 16), (ownerDocument * 9 + checkDispl" ascii
    $s10 = "setter[image](tr.finalValue(), ((createTextNode + -1) | (optgroup, 62, select, 0)), ((amd / 16), (ownerDocument * 9 + checkDispl" ascii
    $s11 = "disconnectedMatch[compile + notifyWith]();" fullword ascii
    $s12 = "while (appendChild[rdisplayswap + on] < (resolveContexts * 2 & (isReady ^ 0))) {" fullword ascii
    $s13 = "script = 238;" fullword ascii
    $s14 = "appendChild[conditionFn + statusCode + unquoted](cssNormalTransform, push + emptyStyle + window + setup + adjustCSS + dataAttr +" ascii
    $s15 = "ache))) / (((648 / resolve) + (4 | visibility)) / ((3 * rfocusable + 2) * (createTextNode + 1)))), ((resolveContexts | 2) ^ (cre" ascii
    $s16 = "deepDataAndEvents[clientX + jsonProp][matcherFromGroupMatchers](((147, extend) / (738 / rcssNum)));" fullword ascii
    $s17 = "setMatched = createElement[noop + rbrace](allTypes + nonce + rcheckableType + unqueued + name);" fullword ascii
    $s18 = "deepDataAndEvents[clientX + nextSibling + random][_default + cacheLength](((ownerDocument * 9 + resolveContexts) - (1 | matchesS" ascii
    $s19 = "deepDataAndEvents[clientX + nextSibling + random][_default + cacheLength](((ownerDocument * 9 + resolveContexts) - (1 | matchesS" ascii
    $s20 = "bind = \"ADO\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}