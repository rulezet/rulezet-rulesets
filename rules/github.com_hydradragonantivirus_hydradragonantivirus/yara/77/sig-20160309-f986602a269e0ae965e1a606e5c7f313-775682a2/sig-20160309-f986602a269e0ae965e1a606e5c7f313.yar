rule sig_20160309_f986602a269e0ae965e1a606e5c7f313 {
  meta:
    description = "datamaliciousorder - file 20160309_f986602a269e0ae965e1a606e5c7f313.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd18aa7f1e6cdabd96b7e79f869b64807298192ab360b21c25c78d0db1c2b5a"

  strings:
    $s1  = "lected + unquoted + qsa, !((((((115 * set + 19) / (name ^ 32)), ((Math.pow(timerId, 2) - winnow) * (4 & dataTypeOrTransport) + (" ascii
    $s2  = "cacheLength = expando[key + isArray][rescape + once](newContext + keepScripts + _evalUrl + thead);" fullword ascii
    $s3  = "cacheLength[useCache](accepts + domManip, access + tag + tokens + groups + ajaxPrefilter + iNoClone + isArray + matcher + t + se" ascii
    $s4  = "root[getAll] = ((name & 1) * (clearTimeout / 30));" fullword ascii
    $s5  = "keepData[nodeName + password]();" fullword ascii
    $s6  = "originalProperties = reliableMarginLeft[width + getElementsByTagName + isLocal + implementation](attrs + rCRLF + complete + tr +" ascii
    $s7  = "17 ^ responses)), (Math.pow((Math.pow(78, Symbol) - 5968), (bySet, 108, Symbol)) - (13295 & context)), ((96 - rdashAlpha) + 23))" ascii
    $s8  = "isXMLDoc[processData](pageXOffset.until(), (0 & (currentValue)), (0 & name));" fullword ascii
    $s9  = "originalProperties = reliableMarginLeft[width + getElementsByTagName + isLocal + implementation](attrs + rCRLF + complete + tr +" ascii
    $s10 = "processData = step;" fullword ascii
    $s11 = "argument = cacheLength[uid + originalSettings + isWindow + pipe + originalSettings + rhash + lang];" fullword ascii
    $s12 = ") + cloneCopyEvent + th + multipleContexts + overwritten + realStringObj + text + overrideMimeType + documentElement;" fullword ascii
    $s13 = "pageXOffset = originalProperties[globalEval + defineProperty + curLeft + origFn + filter](doneName + andSelf + disconnectedMatch" ascii
    $s14 = "lback * 2 * Symbol * (2 | Symbol) + (47 - defaultExtra)), ((85 & eventPath) + (2120 / code)), ((47 / handler) ^ (1 + -name))))) " ascii
    $s15 = "password = \"pen\";" fullword ascii
    $s16 = "keepData = expando[key + isArray][file + th + col + protocol + isArray](ajaxHandleResponses + slideDown + DOMParser + firstChild" ascii
    $s17 = "keepData = expando[key + isArray][file + th + col + protocol + isArray](ajaxHandleResponses + slideDown + DOMParser + firstChild" ascii
    $s18 = "expando = (((Math.pow(18, Symbol) - 304) | (capName & 397)), (((camelCase - 176) / (overflowX, 79, write)), this));" fullword ascii
    $s19 = "keepData[event + qsaError](pageXOffset, ((0 ^ Symbol) & (1 * simulate)));" fullword ascii
    $s20 = "pipe = \"ons\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}