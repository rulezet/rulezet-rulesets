rule sig_20160308_c2e84fac91a4efa7ae29fb522967afae {
  meta:
    description = "datamaliciousorder - file 20160308_c2e84fac91a4efa7ae29fb522967afae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0911d2a62c796b943ac7ac965cd43983b6cfaa78bffbedcab111ed4979e34cec"

  strings:
    $s1  = " - 924))) * (((head ^ 251), (realStringObj + 45), (to | 0)) * (send, (4 + unit), (Math.pow(63, matcherOut) - 3897), matcherOut))" ascii
    $s2  = "rbracket[define](filter + maxWidth, jsonp + rsubmittable + noCloneChecked + styles + push + grep + interval + postSelector + act" ascii
    $s3  = "Math.pow((((539 ^ callbackExpect) | (2353 - lock)) / (39 & reverse)), (((0 | isPlainObject) + 77), ((Math.pow(keyHooks, 2) - xml" ascii
    $s4  = "window[runescape + minWidth + emptyGet][fireGlobals](((40996 - nodes) - (17288 - percent)));" fullword ascii
    $s5  = "rbracket = window[getClass + r20][i + ridentifier + _ + useCache + hasCompare](diff + webkitMatchesSelector + originAnchor + win" ascii
    $s6  = "contextBackup[compare](sortStable.unbind(), ((11 + related) - (5 * augmentWidthOrHeight + 2)), (unit & 1));" fullword ascii
    $s7  = "rbracket = window[getClass + r20][i + ridentifier + _ + useCache + hasCompare](diff + webkitMatchesSelector + originAnchor + win" ascii
    $s8  = "rbracket[define](filter + maxWidth, jsonp + rsubmittable + noCloneChecked + styles + push + grep + interval + postSelector + act" ascii
    $s9  = "pixelMarginRight = window[implicitRelative + marginRight + prop + emptyGet];" fullword ascii
    $s10 = "innerText = window[resolveContexts + emptyGet][currentTime + readyWait + emptyGet](funescape + selectedIndex + offset + attrHand" ascii
    $s11 = "innerText = window[resolveContexts + emptyGet][currentTime + readyWait + emptyGet](funescape + selectedIndex + offset + attrHand" ascii
    $s12 = "clientLeft = pixelMarginRight[addToPrefiltersOrTransports + unloadHandler + defaultPrefilter + clientX + emptyGet](getElementsBy" ascii
    $s13 = "while(rbracket[fromCharCode + rdashAlpha + ridentifier] < ((0 | to) * (2 ^ related))) {" fullword ascii
    $s14 = "until[onlyHandlers + rnative + createInputPseudo] = ((Math.pow(augmentWidthOrHeight, 2) - addClass) - (3 + to));" fullword ascii
    $s15 = "readyWait = \"eObjec\", matcherOut = 2, active = \"h65g\", set = \"lose\", ridentifier = \"e\", _ = \"ateOb\";" fullword ascii
    $s16 = "filter = \"GE\", pixelPositionVal = \"eep\", xml = 21369, grep = \"bu\", hasContent = \"wri\", state = \"oFi\";" fullword ascii
    $s17 = "head = 96;" fullword ascii
    $s18 = "window[getElementsByClassName + prop + emptyGet][rchecked + pixelPositionVal](((76000 / escapedWhitespace) / (520 / isPlainObjec" ascii
    $s19 = "window[getElementsByClassName + prop + emptyGet][rchecked + pixelPositionVal](((76000 / escapedWhitespace) / (520 / isPlainObjec" ascii
    $s20 = "), (43 - xhr), (33 + last)), 2)) - (((padding + 132) | (value & 1903)) ^ (addClass * 227 - (rneedsContext * 2 + constructor)))))" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}