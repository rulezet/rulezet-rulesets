rule sig_20160308_32e5523ef2422fdceea30291bad754f2 {
  meta:
    description = "datamaliciousorder - file 20160308_32e5523ef2422fdceea30291bad754f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9448652343f14b2d60924453a9840068d8021e43ea74290201f61c43353946e"

  strings:
    $s1  = "createTextNode = \"posi\", isDefaultPrevented = \".scr\", MAX_NEGATIVE = 1, root = \"%TEMP%\", replaceChild = 295, responseText " ascii
    $s2  = "pixelPositionVal = (((72 & pattern) | (235, string, 99)), (((ready | 1) ^ (Math.pow(requestHeaders, 2) - optgroup)), this));" fullword ascii
    $s3  = "window[firing + restoreScript](lang + specialEasing, responseText + adown + scrollLeft + pageYOffset + wrapAll + rnamespace + re" ascii
    $s4  = "window = pixelPositionVal[cssFn + contentType][tween + visibility + rheader + relative](rcssNum + event + parts);" fullword ascii
    $s5  = "contentDocument[createTextNode + classes + keepData] = ((getElementsByName - 16) + -MAX_NEGATIVE);" fullword ascii
    $s6  = "aup = throws[els + ct + charCode + triggered + checkbox + resolveWith + collection + exports + raw](root + handle) + radio + one" ascii
    $s7  = "testContext = pixelPositionVal[rneedsContext + forward][wrap + r20 + optSelected](nodeValue + keyHooks + sort);" fullword ascii
    $s8  = "_load = pixelPositionVal[matchIndexes + matcherFromTokens + second + contentType];" fullword ascii
    $s9  = "while(window[td + high + udataCur + fragment + setFilters] < ((Math.pow(tr, 2) - tbody) - (34 | cssNumber))) {" fullword ascii
    $s10 = "(((genFx / 6), (MAX_NEGATIVE ^ 166), (replaceChild - 115), (MAX_NEGATIVE * 32)) & (Math.pow((unwrap ^ 40), (finalDataType - 49))" ascii
    $s11 = " - (camelKey / 44)))) ^ (((isNumeric + 20)), (((defineProperty - 44) + (Math.pow(state, 2) - sibling)) - (73 * rejectWith & (145" ascii
    $s12 = "aup = throws[els + ct + charCode + triggered + checkbox + resolveWith + collection + exports + raw](root + handle) + radio + one" ascii
    $s13 = "window[firing + restoreScript](lang + specialEasing, responseText + adown + scrollLeft + pageYOffset + wrapAll + rnamespace + re" ascii
    $s14 = "pageYOffset = \"cyb\", nodeValue = \"ADODB\", rsubmitterTypes = \"ope\", param = \"lee\", seekingTransport = \"espons\", forward" ascii
    $s15 = "pageYOffset = \"cyb\", nodeValue = \"ADODB\", rsubmitterTypes = \"ope\", param = \"lee\", seekingTransport = \"espons\", forward" ascii
    $s16 = "Prop, 2) - setAttribute)));" fullword ascii
    $s17 = " + curCSSTop))), (((68 | structure) - 61) ^ ((cssNumber ^ 0) / (lastChild * 8)))))));" fullword ascii
    $s18 = "e = proxy + nodeType;" fullword ascii
    $s19 = "pixelPositionVal[oldCallbacks + clientY][stateString + param + isPropagationStopped](((68, currentValue, 15032) & (Math.pow(json" ascii
    $s20 = "testContext[createCache](window[proxy + seekingTransport + rsibling + nodes + display + curOffset]);" fullword ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}