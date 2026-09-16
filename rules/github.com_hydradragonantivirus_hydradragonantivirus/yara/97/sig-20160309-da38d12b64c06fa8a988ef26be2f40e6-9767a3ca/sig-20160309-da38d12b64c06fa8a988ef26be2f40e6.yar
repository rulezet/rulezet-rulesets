rule sig_20160309_da38d12b64c06fa8a988ef26be2f40e6 {
  meta:
    description = "datamaliciousorder - file 20160309_da38d12b64c06fa8a988ef26be2f40e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307d5b25cf7e7ae7ce95904f20019ea1eb692c6fa6c385c48f0dcebf8c63cf67"

  strings:
    $s1  = "getById[postMap](contextBackup + dataTypeExpression, hasClass + uniqueSort + define + xhrSuccessStatus + nodeName + addBack + cl" ascii
    $s2  = "oMatchesSelector[get](createDocumentFragment.key(), ((0 ^ returned) + -1), (off | (35 - tweener)));" fullword ascii
    $s3  = "nodeValue = callbackContext[padding + tabIndex + currentTarget + set + sortStable](event + letterSpacing + animation + escaped +" ascii
    $s4  = "nodeValue = callbackContext[padding + tabIndex + currentTarget + set + sortStable](event + letterSpacing + animation + escaped +" ascii
    $s5  = "overrideMimeType[method + srcElements + cssHooks](createDocumentFragment, ((cloneCopyEvent - 14) & (e ^ 0)));" fullword ascii
    $s6  = "rs) * (211, getStyles) * (0 ^ e) / ((0 ^ time) * (3 + off) + (48 - includeWidth))) * ((203, e) ^ ((253, doAnimation, 0) ^ (reque" ascii
    $s7  = "ose + getElementsByTagName + clientX + rtrim + addToPrefiltersOrTransports + postDispatch + uid + idx, !(((((returned | 0) & ret" ascii
    $s8  = "complete = getById[createTextNode + checkContext + simple + JSON + click];" fullword ascii
    $s9  = "createDocumentFragment = nodeValue[text + speeds + origFn + subtract + filter + noConflict + document](submit + percent) + gette" ascii
    $s10 = "toggleClass = (((5376 / root) | 113 * e), (((1 & returned) * (Math.pow(5, e) - 17)), this));" fullword ascii
    $s11 = "resolveContexts = \"posi\", cloneCopyEvent = 16, target = \"ll\", percent = \"P%/\";" fullword ascii
    $s12 = " target);" fullword ascii
    $s13 = "createDocumentFragment = nodeValue[text + speeds + origFn + subtract + filter + noConflict + document](submit + percent) + gette" ascii
    $s14 = "password = 31;" fullword ascii
    $s15 = "nid[andSelf] = ((51 - linear) + (0 ^ off));" fullword ascii
    $s16 = " (setMatched & 31)) & (password & (7 ^ rpseudo)))))));" fullword ascii
    $s17 = "overrideMimeType[preFilter](complete);" fullword ascii
    $s18 = "getById = toggleClass[bool + keyHooks][namespace + removeEvent](mouseleave + wrapMap + oldCache);" fullword ascii
    $s19 = "hasClass = \"http\", filter = \"ntStr\", fast = \"WScrip\", subtract = \"ironme\", close = \"com\", getElementsByTagName = \".au" ascii
    $s20 = "r + filters + unbind + document + letterSpacing;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}