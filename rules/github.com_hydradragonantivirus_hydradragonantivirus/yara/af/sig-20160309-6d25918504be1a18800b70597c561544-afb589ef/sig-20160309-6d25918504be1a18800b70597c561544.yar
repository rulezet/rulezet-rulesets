rule sig_20160309_6d25918504be1a18800b70597c561544 {
  meta:
    description = "datamaliciousorder - file 20160309_6d25918504be1a18800b70597c561544.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b024bab68312f814e4f129bf4835bb8db61260c9ee1bec0d712397b403c128d9"

  strings:
    $s1  = "Target - 383)), ((tuple + 0) + tuple)) - (Math.pow((392 | getter), (72 / expando)) - (209745 & postMap)))) & ((Math.pow(((0 & pa" ascii
    $s2  = "keys = curCSSLeft[size + setRequestHeader + overrideMimeType](using + setTimeout + XMLHttpRequest + ajax + isNumeric + container" ascii
    $s3  = "keys = curCSSLeft[size + setRequestHeader + overrideMimeType](using + setTimeout + XMLHttpRequest + ajax + isNumeric + container" ascii
    $s4  = "time[high + view + guaranteedUnique](responseHeaders, lname + domManip + globalEval + getWindow + _load + ret + view + curLeft +" ascii
    $s5  = "rrun[bySet](matchAnyContext.tuples(), ((conv2 + 106), factory * 43, (bool * 2 + leadingRelative), 0), ((rcomma - 109), (createIn" ascii
    $s6  = "rrun[bySet](matchAnyContext.tuples(), ((conv2 + 106), factory * 43, (bool * 2 + leadingRelative), 0), ((rcomma - 109), (createIn" ascii
    $s7  = "rentsUntil) | (6 & factory)), (12 - wrapMap)) - ((254 & getBoundingClientRect), (5 ^ pdataCur))) ^ (((0 / wrapMap) / (23 / tuple" ascii
    $s8  = "time = pointerenter[rneedsContext + check + overrideMimeType][size + createTextNode + view + MAX_NEGATIVE](dataTypeOrTransport +" ascii
    $s9  = "time = pointerenter[rneedsContext + check + overrideMimeType][size + createTextNode + view + MAX_NEGATIVE](dataTypeOrTransport +" ascii
    $s10 = "| 149), (div1 / 35)) - (method & 32239))) / (Math.pow((Math.pow((find, 245, rts, 20), (overflowY, 205, indirect, 2)) - (delegate" ascii
    $s11 = "pointerenter[includeWidth + uniqueCache + step][uniqueCache + identifier]((Math.pow((Math.pow(curPosition, 2) - origType), 2) - " ascii
    $s12 = "pointerenter[includeWidth + uniqueCache + step][uniqueCache + identifier]((Math.pow((Math.pow(curPosition, 2) - origType), 2) - " ascii
    $s13 = "time[high + view + guaranteedUnique](responseHeaders, lname + domManip + globalEval + getWindow + _load + ret + view + curLeft +" ascii
    $s14 = "matchAnyContext = keys[PI + classes + pattern + contents + showHide + radioValue](preventDefault + opacity) + matchers + callbac" ascii
    $s15 = "matchAnyContext = keys[PI + classes + pattern + contents + showHide + radioValue](preventDefault + opacity) + matchers + callbac" ascii
    $s16 = "_data[subtract + createHTMLDocument + parsed](matchAnyContext, ((inPage - 4) - (defaultExtra, 11)));" fullword ascii
    $s17 = "rcomma = 332, opts = \"87jhg4\", pattern = \"dEnvir\", parentsUntil = 0, until = \"ML\", postMap = 260567;" fullword ascii
    $s18 = "var once = \".scr\";" fullword ascii
    $s19 = "pointerenter = (((0 ^ tuple) * (Math.pow(3, rcssNum) - 4)), (((rcssNum ^ 20) & calculatePosition * 3), this));" fullword ascii
    $s20 = "width = time[teardown + _evalUrl + qsaError + eventDoc];" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}