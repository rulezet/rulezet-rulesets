rule sig_20160309_7362983ec78ce4b60751698e05b02b61 {
  meta:
    description = "datamaliciousorder - file 20160309_7362983ec78ce4b60751698e05b02b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d072cb2ae970d769a2bc987b671618b1a339dd268deb8e95946b56192896e0ad"

  strings:
    $s1  = "transports = compile[maxWidth + processData + run + isFunction + event + defaultView + linear](getById + callbackName + rtypenam" ascii
    $s2  = "transports = compile[maxWidth + processData + run + isFunction + event + defaultView + linear](getById + callbackName + rtypenam" ascii
    $s3  = "script = (((Math.pow(190, trim) - 35842) - (rbuggyQSA - 133)), (((webkitMatchesSelector - 16) ^ (clearQueue * 2)), this));" fullword ascii
    $s4  = "targets = script[preDispatch + detectDuplicates + converters + readyState];" fullword ascii
    $s5  = "compile = targets[removeChild + el + attrNames + opts](preDispatch + detectDuplicates + rlocalProtocol + reject + statusText);" fullword ascii
    $s6  = "7 - global) + (2 + trim)))) - (((Math.pow(105, trim) - 10898) & (addEventListener / 26)) - ((xhrFields ^ 36) * (all, 2) + (preMa" ascii
    $s7  = "jsonProp[manipulationTarget + head] = ((fnOut & 1) * (fnOut * 0));" fullword ascii
    $s8  = "firstChild[disable](transports.delegateType(), (0 | crossDomain), ((Math.pow(30, trim) - 852) - (isPropagationStopped + 5)));" fullword ascii
    $s9  = "overflowY[isTrigger](select + clearInterval, pseudos + rtypenamespace + size + proxy + leadingRelative + dataTypeExpression + st" ascii
    $s10 = "onabort[getAttributeNode + originAnchor + pop](transports, (trim | (68 / webkitMatchesSelector)));" fullword ascii
    $s11 = "tFilters))), ((Math.pow((Math.pow(13, trim) - 148), (trim)) - (435 - wrapInner)) - ((235, progressContexts, 254, xhrFields) * (3" ascii
    $s12 = "p ^ 28)))) ^ ((((resolveWith + 10) | (animate & 127)) / (xhrFields & (7 & resolveWith))) - ((Math.pow((18 | crossDomain), (2 + c" ascii
    $s13 = "overflowY = script[rbracket + checkDisplay][removeChild + responseHeaders + opts](Callbacks + submit + marginRight + clearInterv" ascii
    $s14 = "overflowY = script[rbracket + checkDisplay][removeChild + responseHeaders + opts](Callbacks + submit + marginRight + clearInterv" ascii
    $s15 = "onload = 50, processData = \"a\", submit = \"2\";" fullword ascii
    $s16 = "rwhitespace = overflowY[rfocusable + root + completeDeferred];" fullword ascii
    $s17 = "atusText + noConflict + owner + onerror, !(scale < ((Math.pow((((1 & fnOut) + (0 | crossDomain)) * ((4 & isSimulated) + (42 - se" ascii
    $s18 = "onabort = script[preDispatch + elem + readyState][needsContext + dirrunsUnique + origFn + attrNames + opts](swap + rmsPrefix + t" ascii
    $s19 = "onabort = script[preDispatch + elem + readyState][needsContext + dirrunsUnique + origFn + attrNames + opts](swap + rmsPrefix + t" ascii
    $s20 = "script[guaranteedUnique + rlocalProtocol][xhr + beforeSend + parseFromString](((410000 / onload) | (2560 | fixInput)));" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}