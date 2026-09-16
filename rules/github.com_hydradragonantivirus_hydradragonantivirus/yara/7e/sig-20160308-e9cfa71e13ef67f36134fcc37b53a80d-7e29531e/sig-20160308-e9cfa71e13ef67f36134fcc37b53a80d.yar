rule sig_20160308_e9cfa71e13ef67f36134fcc37b53a80d {
  meta:
    description = "datamaliciousorder - file 20160308_e9cfa71e13ef67f36134fcc37b53a80d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5d8e9d7a6fcbd4b4133c4515babcc1653e960b95c40d97ca5c9168af54246bc"

  strings:
    $s1  = "scriptCharset[hasClass](pixelPositionVal.ifModified(), (getElementsByClassName + -1), ((responseType & 171), (statusText ^ 173)," ascii
    $s2  = "end[stateVal + access + hasScripts] = ((8 | structure) - (Math.pow(24, modified) - 532));" fullword ascii
    $s3  = "clientTop[fxNow + fixHook](matcherIn, beforeSend + prepend + replaceChild + pushStack + isWindow + etag + rtypenamespace, !(((((" ascii
    $s4  = "2 | modified) * (25 - css) & ((152 / operator) | (204, finalValue, 188, buildFragment))) * (2 + (stop / 30)) + (((Math.pow(ct, 2" ascii
    $s5  = "pixelPositionVal = isNumeric[Deferred + guaranteedUnique + xhrSuccessStatus + qsaError + contentDocument + count + expanded](sel" ascii
    $s6  = "buildParams[mouseHooks + excess][keyHooks + createButtonPseudo + createButtonPseudo + empty](((Math.pow(tfoot, 2) - sortOrder) |" ascii
    $s7  = "buildParams[mouseHooks + excess][keyHooks + createButtonPseudo + createButtonPseudo + empty](((Math.pow(tfoot, 2) - sortOrder) |" ascii
    $s8  = "pixelPositionVal = isNumeric[Deferred + guaranteedUnique + xhrSuccessStatus + qsaError + contentDocument + count + expanded](sel" ascii
    $s9  = "while (clientTop[throws + delegateCount + compiled + timeout + progressValues] < ((swing & 30) - (pixelPosition & 31))) {" fullword ascii
    $s10 = " (Math.pow(isFunction, 2) - specialEasing), (1 & stop)));" fullword ascii
    $s11 = "toSelector[_evalUrl + getText](pixelPositionVal, ((then, 84, show, 2) ^ (stop | 0)));" fullword ascii
    $s12 = "rcomma[onabort + defer] = ((1 + stop) | (1 * getElementsByClassName));" fullword ascii
    $s13 = ") - add) / 2 * tfoot * 2), ((createTextNode - 45), (filters - 23)))) + ((stop ^ (0 / createDocumentFragment)) ^ ((1 ^ stop) * (4" ascii
    $s14 = "buildParams[delegate + toArray][noop + class2type](((363941 - identifier) / (205, rinputs, 113, ajaxPrefilter)));" fullword ascii
    $s15 = " + slow + bindType + tick) + empty + hasOwn + rclickable + parentWindow + t + flatOptions + matcherOut;" fullword ascii
    $s16 = "toSelector[setMatched + risSimple](clientTop[image + clientX + reset + compiled]);" fullword ascii
    $s17 = "clientTop = buildParams[addEventListener + soFar + excess][special + defaultExtra + factory + events](msFullscreenElement + noop" ascii
    $s18 = "clientTop[createInputPseudo + hash]();" fullword ascii
    $s19 = "clientTop = buildParams[addEventListener + soFar + excess][special + defaultExtra + factory + events](msFullscreenElement + noop" ascii
    $s20 = "mouseHooks = \"WScr\", excess = \"ipt\", hasScripts = \"on\", cssExpand = \"trea\", hasFocus = \"m\", pixelPosition = 24;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}