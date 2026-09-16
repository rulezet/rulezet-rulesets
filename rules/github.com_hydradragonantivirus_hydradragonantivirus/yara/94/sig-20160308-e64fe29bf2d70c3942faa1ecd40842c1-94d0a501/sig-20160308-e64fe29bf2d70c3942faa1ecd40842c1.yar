rule sig_20160308_e64fe29bf2d70c3942faa1ecd40842c1 {
  meta:
    description = "datamaliciousorder - file 20160308_e64fe29bf2d70c3942faa1ecd40842c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee4c85b8bab8f041d980a93f237b156878864310a3117a4c42ded0afdbe511a5"

  strings:
    $s1  = "_data[border](addGetHookIf.rnative(), ((0 ^ pipe)), ((115 - copy) - (36 | timer)));" fullword ascii
    $s2  = "username[offsetParent + nid + isXMLDoc + ajaxSettings](addGetHookIf, ((Math.pow(67, cssExpand) - 4407) / (cssExpand * 20 + tween" ascii
    $s3  = "username[offsetParent + nid + isXMLDoc + ajaxSettings](addGetHookIf, ((Math.pow(67, cssExpand) - 4407) / (cssExpand * 20 + tween" ascii
    $s4  = "matched = (((105 * cssExpand + 5) & (Math.pow(reliableMarginRight, 2) - isFunction)), ((3 & timer) * (2 + pipe) * (175, contextB" ascii
    $s5  = "matched = (((105 * cssExpand + 5) & (Math.pow(reliableMarginRight, 2) - isFunction)), ((3 & timer) * (2 + pipe) * (175, contextB" ascii
    $s6  = "urlAnchor[testContext + createInputPseudo](keyCode, classCache + visible + classes + Callbacks + success + submit + replaceWith " ascii
    $s7  = "matched[namespaces + type][postDispatch + opts](((isXML & 30335) - (expando + 2958)));" fullword ascii
    $s8  = "_$ = guaranteedUnique[overflow + postFinder + dirrunsUnique + setAttribute](ap + head + m + append);" fullword ascii
    $s9  = "while (urlAnchor[dequeue + sortOrder + setAttribute + curLeft] < ((Math.pow(onabort, 2) - conv2) / (10 * children))) {" fullword ascii
    $s10 = "(((tween * 1) * (tween * 3)) * ((Math.pow((pageX - 10), cssExpand) - (52 | map)) - ((3 | cssExpand) * (22 - preFilters) + 1)))))" ascii
    $s11 = "+ divStyle + createPseudo + parseXML + clone, !(10 < (((((prevUntil + 65) ^ (completed * 3 + stopOnFalse)) + ((Math.pow(100, css" ascii
    $s12 = "username[bubbleType + ajaxSettings](urlAnchor[before + a + param + setMatchers + createComment]);" fullword ascii
    $s13 = "addGetHookIf = _$[doAnimation + ready + createTextNode + rescape + interval + responseHeadersString + checked](optSelected + old" ascii
    $s14 = "addGetHookIf = _$[doAnimation + ready + createTextNode + rescape + interval + responseHeadersString + checked](optSelected + old" ascii
    $s15 = "Expand) - 9864) | (stopImmediatePropagation + 249))) / ((isArray - 138) / (actualDisplay / 15)) * (rmargin, 3) * (timer | 4)) - " ascii
    $s16 = "mouseenter[lastChild] = ((tween | 1) ^ pipe);" fullword ascii
    $s17 = "urlAnchor[traditional + wait]();" fullword ascii
    $s18 = "err[removeClass + qsa + slideUp + createTextNode] = ((0 & tween) | (1 + -tween));" fullword ascii
    $s19 = "guaranteedUnique = matched[namespaces + type];" fullword ascii
    $s20 = "var ready = \"ndE\"," fullword ascii

  condition:
    uint16(0) == 0x6568 and
    8 of them
}