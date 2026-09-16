rule sig_20160307_65b563d18408ff068c3e737cb8224eb5 {
  meta:
    description = "datamaliciousorder - file 20160307_65b563d18408ff068c3e737cb8224eb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668d3552a642d5f0cebdc062323de6bdc056e0876f2cdbf3cf52ce07908e44ef"

  strings:
    $x1  = "noBubble[clone](defineProperty, errorCallback + cssNormalTransform + support + overflowY + onerror + outermost + qsa + mozMatche" ascii
    $s2  = "sSelector + contents + source + getAttribute + swap, !(3 < (((speeds * 2 * speeds ^ (11 - expanded)) - (((11 & els) & (330 / con" ascii
    $s3  = "completed[getStyles + blur + ajaxSetup + reset + ajaxSetup](removeEvent, ((21, init, 221, ajaxHandleResponses) | (3 & readyState" ascii
    $s4  = "removeEvent = holdReady[addHandle + fixHooks + random + not + head + addCombinator](stored + xhr) + preventDefault + minWidth + " ascii
    $s5  = "removeEvent = holdReady[addHandle + fixHooks + random + not + head + addCombinator](stored + xhr) + preventDefault + minWidth + " ascii
    $s6  = "completed[getStyles + blur + ajaxSetup + reset + ajaxSetup](removeEvent, ((21, init, 221, ajaxHandleResponses) | (3 & readyState" ascii
    $s7  = "parents[jsonProp + letter][linear + progress](((Math.pow(229, readyState) - 52197), (removeData ^ 119)));" fullword ascii
    $s8  = "tainer)) & 3 * speeds)) - (((1 ^ ajaxHandleResponses) + ((25 - rscriptType))) | ((198, Deferred, 1) - ((outerCache, 188, configu" ascii
    $s9  = "method[merge](removeEvent.newDefer(), (3 * speeds * 5 - (Deferred - 93)), ((username / 10), (setTimeout | 159), (url - 50), (res" ascii
    $s10 = "method[merge](removeEvent.newDefer(), (3 * speeds * 5 - (Deferred - 93)), ((username / 10), (setTimeout | 159), (url - 50), (res" ascii
    $s11 = "completed[addToPrefiltersOrTransports + percent + ajaxSetup]();" fullword ascii
    $s12 = "parents[fns + state + _jQuery][linear + progress](((rscriptType * 5 + els) * (10 | nodeNameSelector) + 15));" fullword ascii
    $s13 = "var outermost = \"3.com.\"," fullword ascii
    $s14 = "completed[proxy](noBubble[animated + ajaxExtend + truncate]);" fullword ascii
    $s15 = "rable) / (65 - container)))))));" fullword ascii
    $s16 = "winnow[qualifier] = ((speeds - 3) | (responseFields ^ 0));" fullword ascii
    $s17 = "completed[open + etag]();" fullword ascii
    $s18 = "completed = parents[rsingleTag + _jQuery][hasFocus + doneName + leadingRelative](focusin + handlerQueue + always + timeoutTimer)" ascii
    $s19 = "while (noBubble[list + udataCur + stop + optionSet + ajaxSetup] < ((1 + ajaxHandleResponses) + (1 ^ readyState))) {" fullword ascii
    $s20 = "parents = ((1 ^ readyState) * (3 + ajaxHandleResponses) * (3 & readyState), (((2 + ajaxHandleResponses) * (0 | readyState) + (17" ascii

  condition:
    uint16(0) == 0x6568 and
    1 of ($x*) and 4 of them
}