rule sig_20160307_407db2e709d2e6a473051781d67111ee {
  meta:
    description = "datamaliciousorder - file 20160307_407db2e709d2e6a473051781d67111ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df63294e69a777c58cdb62fcb6f8e24bc8a58272d3a8142d9a747dfe709fdd1"

  strings:
    $x1  = "getClass[fadeIn + finalDataType](promise, rnoInnerhtml + iterator + Data + ajaxSettings + seed + password + evt + checked + mime" ascii
    $s2  = "2), (bindType * 5 + hold), (0 | i)))) / ((((138 - keepScripts) + (12 & bindType))) - (Math.pow(29, ((i & 0) ^ (offsetParent * 2)" ascii
    $s3  = "getClass = pnum[firing + inPage + off + matches][checkOn + password + fadeTo + tabIndex + setMatcher](matchesSelector + callback" ascii
    $s4  = "getClass = pnum[firing + inPage + off + matches][checkOn + password + fadeTo + tabIndex + setMatcher](matchesSelector + callback" ascii
    $s5  = "getClass[fadeIn + finalDataType](promise, rnoInnerhtml + iterator + Data + ajaxSettings + seed + password + evt + checked + mime" ascii
    $s6  = "pnum = (((111 - cssFn) * 2 * curCSSTop + (9 | offsetParent)), ((Math.pow((3 ^ i), (170, defaultValue, 181, curCSSTop)) - (2 * cu" ascii
    $s7  = "find[dest + matches + headers] = ((attrId, 11, hold, 0) | i);" fullword ascii
    $s8  = "while(getClass[active + setTimeout + dataShow] < ((1 * offsetParent) + (24 - doAnimation))) {" fullword ascii
    $s9  = "onerror[id](getClass[file + responseType + newUnmatched]);" fullword ascii
    $s10 = "var password = \"r\"," fullword ascii
    $s11 = "_data = abort[timer + window + isDefaultPrevented + tag + isNumeric + appendChild + addCombinator](cloneNode + setOffset) + reli" ascii
    $s12 = "var position = \".scr\"," fullword ascii
    $s13 = "abort = removeAttr[extend + prefix + setMatcher](before + binary + now);" fullword ascii
    $s14 = "_data = abort[timer + window + isDefaultPrevented + tag + isNumeric + appendChild + addCombinator](cloneNode + setOffset) + reli" ascii
    $s15 = "Type + scrollTop, !((((((cacheURL * 5 + hold) - (Math.pow(48, curCSSTop) - 2222)), ((reset + 38) - (animation ^ 74)), ((rparents" ascii
    $s16 = "onerror[apply + offset]();" fullword ascii
    $s17 = "onerror[siblingCheck + eventHandle](_data, ((1 + hold), (110 ^ base), (221 & overflowX), 2));" fullword ascii
    $s18 = "binary = \"pt.She\"," fullword ascii
    $s19 = "window = \"xpandE\", dest = \"posi\", setTimeout = \"sta\", promise = \"GET\", apply = \"clos\", fireGlobals = (function String." ascii
    $s20 = "window = \"xpandE\", dest = \"posi\", setTimeout = \"sta\", promise = \"GET\", apply = \"clos\", fireGlobals = (function String." ascii

  condition:
    uint16(0) == 0x6166 and
    1 of ($x*) and 4 of them
}