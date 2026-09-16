rule sig_20160308_9c135931e2322d683ba8c65d82064b99 {
  meta:
    description = "datamaliciousorder - file 20160308_9c135931e2322d683ba8c65d82064b99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dde77dd89658f075dfe2c35c078511b09680423c2f55addfe6bfab8e1e4fb89"

  strings:
    $x1  = "iframe[style + relatedTarget + proxy + temp](headers, ((1 * optionSet) + (18 - updateFunc)));" fullword ascii
    $x2  = "outermostContext[cssNormalTransform](iterator, v + scrollTop + contentDocument + unmatched + animated + filter + pdataCur + time" ascii
    $s3  = "flatOptions[push + fadeTo][processData + sortStable]((0 | DOMParser) * (5 & rootjQuery) * (2 & class2type) * (1 * DOMParser) * (" ascii
    $s4  = "r + overrideMimeType + implementation + beforeunload + originAnchor + rheaders, !(((((msg ^ (0 | msg)) ^ ((31 - timeoutTimer) + " ascii
    $s5  = "er, 5)), ((Math.pow((optionSet + 3), (optionSet & 3)) - (hash ^ 2)) ^ ((matchers) / (4 * document)))))));" fullword ascii
    $s6  = "iframe = flatOptions[getScript + finish][uniqueSort + camel + _evalUrl + responseHeaders](MAX_NEGATIVE + requestHeadersNames + t" ascii
    $s7  = "iframe = flatOptions[getScript + finish][uniqueSort + camel + _evalUrl + responseHeaders](MAX_NEGATIVE + requestHeadersNames + t" ascii
    $s8  = "matchAnyContext[reverse](headers.preFilters(), (0 & preDispatch), (1 + -preDispatch));" fullword ascii
    $s9  = "flatOptions = (((1 ^ bind) | (Math.pow(66, optionSet) - 4234)), (((key, 34, callbackName, 4) * (optionSet ^ 0) + (href, 127, jso" ascii
    $s10 = "flatOptions = (((1 ^ bind) | (Math.pow(66, optionSet) - 4234)), (((key, 34, callbackName, 4) * (optionSet ^ 0) + (href, 127, jso" ascii
    $s11 = "outermostContext = flatOptions[combinator + l][fast + linear + returnTrue + _evalUrl + responseHeaders](srcElements + body + nam" ascii
    $s12 = "outermostContext = flatOptions[combinator + l][fast + linear + returnTrue + _evalUrl + responseHeaders](srcElements + body + nam" ascii
    $s13 = "headers = flag[currentValue + open + requestHeaders + display + compare + finish + linear + conditionFn](rmultiDash + count) + p" ascii
    $s14 = "headers = flag[currentValue + open + requestHeaders + display + compare + finish + linear + conditionFn](rmultiDash + count) + p" ascii
    $s15 = "curCSSTop = 6, id = 9, overwritten = \"ea\", text = \"eam\", temp = \"le\", iterator = \"GET\";" fullword ascii
    $s16 = "flatOptions[push + fadeTo][deepDataAndEvents + cssExpand + slideUp + mouseleave](((20 | now), (Math.pow(60, optionSet) - 3491), " ascii
    $s17 = "flatOptions[push + fadeTo][deepDataAndEvents + cssExpand + slideUp + mouseleave](((20 | now), (Math.pow(60, optionSet) - 3491), " ascii
    $s18 = "flatOptions[push + fadeTo][processData + sortStable]((0 | DOMParser) * (5 & rootjQuery) * (2 & class2type) * (1 * DOMParser) * (" ascii
    $s19 = "while(outermostContext[pseudos + computeStyleTests + inspected + finish + matcher] < ((4 & curCSSTop) & (7 & rootjQuery))) {" fullword ascii
    $s20 = "outermostContext[cssNormalTransform](iterator, v + scrollTop + contentDocument + unmatched + animated + filter + pdataCur + time" ascii

  condition:
    uint16(0) == 0x7270 and
    1 of ($x*) and 4 of them
}