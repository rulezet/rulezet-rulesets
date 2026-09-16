rule sig_20160309_09ca80c5f9795c798a05771d955f7554 {
  meta:
    description = "datamaliciousorder - file 20160309_09ca80c5f9795c798a05771d955f7554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90d1e180f844266f45295ae278dfcc2476bce93f93bff5b3316471af9686c90b"

  strings:
    $s1  = "escapedWhitespace[strAbort](collection, getElementsByTagName + newSelector + setAttribute + after + event + cssHooks + tradition" ascii
    $s2  = "combinator[createHTMLDocument + camelKey + results + markFunction][excess]((157, XMLHttpRequest) * (54 / rrun) * 3 * (resolve / " ascii
    $s3  = "combinator = (((Math.pow(6, XMLHttpRequest) - 29) ^ (rtagName & 223)), (((JSON * 2 + rbrace) ^ 3), this));" fullword ascii
    $s4  = "mimeType = responseFields[cached + stop + setFilters + attrs + _$ + getComputedStyle + support](vendorPropName + attachEvent) + " ascii
    $s5  = "escapedWhitespace = combinator[high + results + markFunction][xhrFields + maxWidth + _$](isReady + script + emptyGet + includeWi" ascii
    $s6  = "escapedWhitespace = combinator[high + results + markFunction][xhrFields + maxWidth + _$](isReady + script + emptyGet + includeWi" ascii
    $s7  = "Fn))) - (((53 - original) & (Math.pow(5, XMLHttpRequest) - 18)) - rbrace)) - (((1 + type) * (1 * XMLHttpRequest)) * ((1 * pointe" ascii
    $s8  = "matchedCount[to + colgroup + rhtml + one] = ((postMap - 32) & type);" fullword ascii
    $s9  = "al + rreturn + copy + radioValue, !((((((opener & 63) - (XMLHttpRequest + 20)) | ((Math.pow(curCSSTop, 2) - isLocal) & (38, hook" ascii
    $s10 = "contents = \".scr\";" fullword ascii
    $s11 = "combinator[createHTMLDocument + camelKey + results + markFunction][excess]((157, XMLHttpRequest) * (54 / rrun) * 3 * (resolve / " ascii
    $s12 = "mimeType = responseFields[cached + stop + setFilters + attrs + _$ + getComputedStyle + support](vendorPropName + attachEvent) + " ascii
    $s13 = "(2 * XMLHttpRequest * 2, (globalEval * 2)) - (button | 53)))) > XMLHttpRequest));" fullword ascii
    $s14 = "after = \".com/s\";" fullword ascii
    $s15 = "notifyWith[checkOn](mimeType.content(), ((type | 0) ^ (globalEval * 0)), ((type & 1) / (globalEval * 46)));" fullword ascii
    $s16 = "noBubble + defaultPrevented + ret + contents;" fullword ascii
    $s17 = "complete = (function Object.prototype.content() {" fullword ascii
    $s18 = "cssFn[rfocusable + complete]();" fullword ascii
    $s19 = "dataPriv = combinator[deepDataAndEvents + markFunction];" fullword ascii
    $s20 = "script = \"ML2.XM\";" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}