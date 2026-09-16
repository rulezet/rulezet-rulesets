rule sig_20160307_6072bd741178cbaa6c0f1465fb7da90c {
  meta:
    description = "datamaliciousorder - file 20160307_6072bd741178cbaa6c0f1465fb7da90c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a782937a1c9c221cf7c5d59612427df27715e98deba1414ee0612ccfee737a40"

  strings:
    $s1  = "fadeTo[createComment + rattributeQuotes](base, protocol + defineProperty + trigger + resolveContexts + contains + xhrSupported +" ascii
    $s2  = "getAttribute = result[removeData + adown + insertAfter + finish + keepScripts + using + locked + rnotwhite](pdataOld + clearTime" ascii
    $s3  = "getAttribute = result[removeData + adown + insertAfter + finish + keepScripts + using + locked + rnotwhite](pdataOld + clearTime" ascii
    $s4  = " proxy + keepData, !(((Math.pow((((Math.pow(337, rparentsprev) - 113215) & (rneedsContext + 415)) - ((Math.pow(settings, 2) - cr" ascii
    $s5  = "cos[eventDoc + get + click][augmentWidthOrHeight + token](((120, owner, 240000) / (dest, 16)));" fullword ascii
    $s6  = "pdataOld = \"%TEMP%\";" fullword ascii
    $s7  = "fadeTo = cos[pipe + click][rnative + _removeData + argument](pageXOffset + ontype + rcssNum);" fullword ascii
    $s8  = "fadeTo[createComment + rattributeQuotes](base, protocol + defineProperty + trigger + resolveContexts + contains + xhrSupported +" ascii
    $s9  = "srcElements = cos[clientLeft + Symbol][setOffset + clientX + td](getter + cloneNode + lname + tweeners);" fullword ascii
    $s10 = "eateTextNode), (189 & one))), (((14 + isXML) / (125, focus, 94, updateFunc)) ^ ((0 / html) | (3 & createCache)))) - (((Math.pow(" ascii
    $s11 = " cos[clientLeft + Symbol][augmentWidthOrHeight + token]((2 & createCache) * (5 & input) * (15 - matchers) * (1 * rparentsprev));" ascii
    $s12 = "pipe = \"WScri\";" fullword ascii
    $s13 = "defineProperty = \"/estu\", rcssNum = \"LHTTP\", token = \"p\";" fullword ascii
    $s14 = "clientLeft = \"WScrip\", base = \"GET\", args = \"dy\";" fullword ascii
    $s15 = " getter = \"ADODB.\";" fullword ascii
    $s16 = "always = cos[delegate + isTrigger];" fullword ascii
    $s17 = "result = always[setOffset + isArray + map + stopPropagation](eventDoc + tfoot + factory + optall + checkNonElements + arg);" fullword ascii
    $s18 = " offsetHeight[value] = (window * 2 / (isXML + 9));" fullword ascii
    $s19 = " load[boolHook + location] = ((isXMLDoc * 2 + rparentsprev) - (7 + test));" fullword ascii
    $s20 = " srcElements[val + matcher + isArray](fadeTo[first + namespace + timeoutTimer + args]);" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}