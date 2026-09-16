rule sig_20160308_1d489575d6ae3cf7ce4b730c991a8729 {
  meta:
    description = "datamaliciousorder - file 20160308_1d489575d6ae3cf7ce4b730c991a8729.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ebd5febf727625936b9c7d68708bdfd3a5399a3626d53d4f76267ec4c3c1e14"

  strings:
    $s1  = "activeElement = seekingTransport[value + currentTarget + relative + completed + count + evt + rscriptTypeMasked](propName + rtyp" ascii
    $s2  = "activeElement = seekingTransport[value + currentTarget + relative + completed + count + evt + rscriptTypeMasked](propName + rtyp" ascii
    $s3  = "defaultValue[script + postFinder][getResponseHeader + beforeSend](((flatOptions | 13441) ^ (Math.pow(noCloneChecked, 2) - newCac" ascii
    $s4  = "defaultValue[script + postFinder][getResponseHeader + beforeSend](((flatOptions | 13441) ^ (Math.pow(noCloneChecked, 2) - newCac" ascii
    $s5  = "easing = defaultValue[script + pointerleave + parseJSON][removeChild + getElementsByTagName + rbuggyMatches + nodeNameSelector](" ascii
    $s6  = "conv[traditional + proxy + contexts] = ((88, $, 0) ^ (hash - 30));" fullword ascii
    $s7  = "+ matchAnyContext + orig, !((Math.pow(((((not & 77) / (xhrSupported & 54)) * ((done | 3) & globalEval)) + (((1 + -pageYOffset) |" ascii
    $s8  = "4130)) / ((cssText + 12) ^ (Math.pow(xhrSupported, 2) - apply))))) - (((1 | done) + (24 / timerId)) * ((36, globalEval) - 1) * (" ascii
    $s9  = "easing[identifier + addHandle](register, srcElements + classCache + bulk + has + originalEvent + mozMatchesSelector + cloneNode " ascii
    $s10 = "set = defaultValue[configurable + wait + postFinder];" fullword ascii
    $s11 = "easing = defaultValue[script + pointerleave + parseJSON][removeChild + getElementsByTagName + rbuggyMatches + nodeNameSelector](" ascii
    $s12 = "html[detach + pageY + qsaError + _](activeElement, ((div - 45) & (pageYOffset ^ 2)));" fullword ascii
    $s13 = " (0 | done)) ^ ((1 + done) * (1 ^ elementMatchers)))), (((1 * pageYOffset)) * (((8 + fadeIn) ^ (Math.pow(65, elementMatchers) - " ascii
    $s14 = "defaultValue = (((271 - fadeIn) & (248 & ofType)), (((14 & initialInUnit) ^ (180, t, 1)), this));" fullword ascii
    $s15 = "fadeIn - (21 & pixelPosition)) + (((19 ^ method) | (73 - pixelPosition)) & ((83 * elementMatchers + 23) / (pageYOffset + 2))))) " ascii
    $s16 = "seekingTransport = set[removeChild + guaranteedUnique + ajaxSettings + toSelector + parseJSON](protocol + collection + valuePart" ascii
    $s17 = "defaultValue[configurable + queue + evt + pointerleave + parseJSON][sortOrder + parseXML](((166, isFunction, 151), (beforeunload" ascii
    $s18 = "defaultValue[configurable + queue + evt + pointerleave + parseJSON][sortOrder + parseXML](((166, isFunction, 151), (beforeunload" ascii
    $s19 = "seekingTransport = set[removeChild + guaranteedUnique + ajaxSettings + toSelector + parseJSON](protocol + collection + valuePart" ascii
    $s20 = "enamespace) + evt + document + nextSibling + addToPrefiltersOrTransports + wait;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}