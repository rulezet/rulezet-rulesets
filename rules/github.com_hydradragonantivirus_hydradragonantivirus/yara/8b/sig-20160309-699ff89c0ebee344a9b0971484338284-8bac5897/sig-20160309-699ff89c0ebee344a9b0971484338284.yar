rule sig_20160309_699ff89c0ebee344a9b0971484338284 {
  meta:
    description = "datamaliciousorder - file 20160309_699ff89c0ebee344a9b0971484338284.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17d5adfbed84a90db2452285ded76d4db79239251a6ddc265453250641d6d207"

  strings:
    $x1  = "adjusted[parsed](stopped, copyIsArray + adjustCSS + obj + rxhtmlTag + ready + box + password + onabort + code + ret + resolveWit" ascii
    $s2  = "adjusted = border[ontype + delegateTarget][valHooks + keepScripts + host](callbackInverse + propName + iframe);" fullword ascii
    $s3  = "args = \"%TEMP\", manipulationTarget = 3, e = \"WScr\", height = 23, parsed = \"open\", host = \"ect\";" fullword ascii
    $s4  = "wrap = border[stopQueue + appendChild + minWidth][firstElementChild + linear + cssProps + addToPrefiltersOrTransports + delegate" ascii
    $s5  = "code = \"c\", ret = \"om/23\", getStyles = 19, file = 9, marginRight = \"Script\", password = \"web.\";" fullword ascii
    $s6  = "3 * manipulationTarget + 8)) / (getAttributeNode + 1) * (nodeType, 7) * (postFinder, 197, manipulationTarget)), (((375 - special" ascii
    $s7  = "Target](curValue + cloneCopyEvent + token + inArray + list);" fullword ascii
    $s8  = "adjusted[parsed](stopped, copyIsArray + adjustCSS + obj + rxhtmlTag + ready + box + password + onabort + code + ret + resolveWit" ascii
    $s9  = "isWindow[selected + prefix] = (17 * matchIndexes * 3, (needsContext, 37, file), (393 - pdataOld), (36 - getClientRects));" fullword ascii
    $s10 = "disable = win[speeds + events + to + configurable + blur + curCSSLeft + uniqueID + contents](args + firing + func) + selection +" ascii
    $s11 = "disable = win[speeds + events + to + configurable + blur + curCSSLeft + uniqueID + contents](args + firing + func) + selection +" ascii
    $s12 = "h + className, !(((getAttributeNode & 1) ^ ((getAttributeNode * 2) | (height - 20))) * (Math.pow((((fns * 4 + matchIndexes) - (3" ascii
    $s13 = "border[stopQueue + marginRight][ajaxSettings]((Math.pow((333678 / col), 2) - (disabled | 8392832)));" fullword ascii
    $s14 = "border = (((Math.pow(31, inPage) - 917) + (timers - 198)), ((height - 20), this));" fullword ascii
    $s15 = "win = firingIndex[valHooks + push_native + eq + host](e + nodeName + pos + raw + nid);" fullword ascii
    $s16 = "wrap[cssExpand + documentElement](disable, (28 - insertBefore));" fullword ascii
    $s17 = "etStyles - 13)) / ((handler - 13), (wrapAll / 31), (errorCallback | 10)))) > serializeArray));" fullword ascii
    $s18 = "wrap = border[stopQueue + appendChild + minWidth][firstElementChild + linear + cssProps + addToPrefiltersOrTransports + delegate" ascii
    $s19 = "contents = \"gs\";" fullword ascii
    $s20 = "stopped = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}