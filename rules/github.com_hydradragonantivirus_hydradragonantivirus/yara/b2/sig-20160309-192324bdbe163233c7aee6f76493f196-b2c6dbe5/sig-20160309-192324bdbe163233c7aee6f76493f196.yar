rule sig_20160309_192324bdbe163233c7aee6f76493f196 {
  meta:
    description = "datamaliciousorder - file 20160309_192324bdbe163233c7aee6f76493f196.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2236f0c754cae204da0b2084f54c8ab7f61c573f7a54ff876d4cb1ebf738b8e"

  strings:
    $s1  = "createButtonPseudo[stopOnFalse + dataTypeExpression](fcamelCase, responseHeaders + firstElementChild + isEmptyObject + namespace" ascii
    $s2  = "getAllResponseHeaders = (((377 - dispatch) & (1900 / offsetWidth)), ((Math.pow((Math.pow(11, expando) - 105), expando) - (134 | " ascii
    $s3  = "/ (107 - getAttribute)) | ((238, success, 6) + (proxy, 32, not)))))));" fullword ascii
    $s4  = "getAllResponseHeaders = (((377 - dispatch) & (1900 / offsetWidth)), ((Math.pow((Math.pow(11, expando) - 105), expando) - (134 | " ascii
    $s5  = "setFilters = getAllResponseHeaders[rbuggyMatches + appendTo][insertBefore + hooks + rcomma](xhrFields + _jQuery + support);" fullword ascii
    $s6  = "createButtonPseudo = getAllResponseHeaders[_data + getResponseHeader][excess + complete + responses + originAnchor + run](postFi" ascii
    $s7  = "createButtonPseudo = getAllResponseHeaders[_data + getResponseHeader][excess + complete + responses + originAnchor + run](postFi" ascii
    $s8  = " (((170, opener, 32) | (els * 6)), ((checkDisplay - 31) & (createComment ^ 0)))) + ((Math.pow(((inspect * 2 + using) / (8 | offs" ascii
    $s9  = "onload = combinator[m + attr + bup + removeEventListener + parseHTML + rpseudo](addHandle + style + round) + rpseudo + nonce + c" ascii
    $s10 = "onload = combinator[m + attr + bup + removeEventListener + parseHTML + rpseudo](addHandle + style + round) + rpseudo + nonce + c" ascii
    $s11 = "combinator = rrun[delegateType + matcherFromGroupMatchers + outermostContext + originalEvent + has](handleObj + padding + preexi" ascii
    $s12 = "find = createButtonPseudo[reject + rpseudo + prefix + rscriptTypeMasked + createPseudo];" fullword ascii
    $s13 = "getAllResponseHeaders[rescape + clone][targets + ajaxSettings]((2 * protocol * 23 * expando * 5 * expando * 5 * protocol * 3 / (" ascii
    $s14 = "getAllResponseHeaders[rescape + clone][targets + ajaxSettings]((2 * protocol * 23 * expando * 5 * expando * 5 * protocol * 3 / (" ascii
    $s15 = "combinator = rrun[delegateType + matcherFromGroupMatchers + outermostContext + originalEvent + has](handleObj + padding + preexi" ascii
    $s16 = "returned[headers + realStringObj]();" fullword ascii
    $s17 = "rrun = getAllResponseHeaders[rescape + clone];" fullword ascii
    $s18 = " + elemData + cssText + curLeft + elements + method + isPlainObject + sort, !(8 < (((((pos - 35)) ^ isHidden * (1 * isHidden)) &" ascii
    $s19 = "offsetHeight = \"send\", headers = \"c\", responses = \"e\", method = \"gh\";" fullword ascii
    $s20 = "replaceAll[shift](onload.clientY(), ((1 + -preDispatch) & (2 - preDispatch)), ((19 - not) ^ (1 * escapedWhitespace)));" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}