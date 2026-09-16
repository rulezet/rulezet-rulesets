rule sig_20160309_509d8e43565b963eeab6e7dfd3af09ea {
  meta:
    description = "datamaliciousorder - file 20160309_509d8e43565b963eeab6e7dfd3af09ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a547f5b3d812912b73eda4299ca94e4ea1ddcbc7c90d0c99a5ec46e1e56528b9"

  strings:
    $s1  = "filters[complete](temp.fadeOut(), ((preDispatch & 1) * (preDispatch + -1)), (rkeyEvent ^ 0));" fullword ascii
    $s2  = "dth + show + configurable + overwritten + nodeType + ready, !((((((preDispatch ^ 3) + (rkeyEvent | 0)) * ((rcleanScript & 7) & (" ascii
    $s3  = "base[adjusted](hasFocus + sel, setGlobalEval + slow + empty + beforeSend + stopImmediatePropagation + preexisting + args + maxWi" ascii
    $s4  = "selector[image + focusin + createOptions + pixelMarginRightVal](temp, ((elementMatcher | 18) / (manipulationTarget & 31)));" fullword ascii
    $s5  = "temp = unloadHandler[getById + win + rsingleTag + cssExpand + webkitMatchesSelector + width + oMatchesSelector](simple + opt + i" ascii
    $s6  = "reliableMarginLeftVal - 17))) * (((createElement - 7) * padding + 1) & ((second | 13) - (rcleanScript ^ 0))) + ((preDispatch + -" ascii
    $s7  = "hasData[firstElementChild + pattern] = ((0 | async) - (7 & rcleanScript));" fullword ascii
    $s8  = "conditionFn = ((11 * computed & 151), (((setRequestHeader & 61) / (padding ^ 4)), this));" fullword ascii
    $s9  = "temp = unloadHandler[getById + win + rsingleTag + cssExpand + webkitMatchesSelector + width + oMatchesSelector](simple + opt + i" ascii
    $s10 = " + ((reliableMarginLeft & 18) | (rkeyEvent | 16))))) > push));" fullword ascii
    $s11 = "base = conditionFn[hidden + each][arr + leadingRelative + nodeIndex + dataTypeOrTransport + xhrFields](structure + hasOwnPropert" ascii
    $s12 = "ontype[docElem + getClientRects] = (0 | (preDispatch & 0));" fullword ascii
    $s13 = "unloadHandler = timeout[setAttribute + left + func](sourceIndex + scale + errorCallback + compilerCache + throws + support);" fullword ascii
    $s14 = "setup = base[rnative + returnValue + getWidthOrHeight + maxIterations];" fullword ascii
    $s15 = "conditionFn[sourceIndex + classCache][password](((testContext + 2390) | (ajaxSettings ^ 14469)));" fullword ascii
    $s16 = "password = \"Sleep\";" fullword ascii
    $s17 = "base = conditionFn[hidden + each][arr + leadingRelative + nodeIndex + dataTypeOrTransport + xhrFields](structure + hasOwnPropert" ascii
    $s18 = "complete = onreadystatechange;" fullword ascii
    $s19 = "setRequestHeader = 60, param = \"send\", slow = \"tp\", sel = \"ET\", emptyStyle = \"ose\";" fullword ascii
    $s20 = "getter = \"MP\"," fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}