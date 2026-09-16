rule sig_20160308_ce85fa1372b944bc3043291b4a6a98ca {
  meta:
    description = "datamaliciousorder - file 20160308_ce85fa1372b944bc3043291b4a6a98ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e898a572e733906613ea9b7857c2cde480d358ffaabb721b6f3c5d7b65903606"

  strings:
    $s1  = "timeout + excess, !((((((getById / 39) | (hasCompare, 10, slideUp, 198)), (Math.pow((addCombinator | 0), (charCode / 44)) - (tup" ascii
    $s2  = "pdataOld[events + rquery](triggered, ret + method + removeAttr + expando + matchContext + cssPrefixes + checkContext + getAll + " ascii
    $s3  = "el[stopQueue + state][dataTypeOrTransport + getWindow](((7099 & border) * (2 + ownerDocument) + (2630 & unquoted)));" fullword ascii
    $s4  = "compare[second + sortStable] = ((1 + -prev) ^ (1 + ownerDocument));" fullword ascii
    $s5  = "pdataOld[events + rquery](triggered, ret + method + removeAttr + expando + matchContext + cssPrefixes + checkContext + getAll + " ascii
    $s6  = "var getter = \"Run\"," fullword ascii
    $s7  = "el = ((103 * pageXOffset - (45 * p + 22)), (((max / 47) + (rbracket - 11)), this));" fullword ascii
    $s8  = "event = toSelector[Symbol + pageY + clientX + rquickExpr + setMatched + namespace + now](oldfire + using + tokenize) + prependTo" ascii
    $s9  = "toSelector = pointerenter[replaceAll + hasOwnProperty + safeActiveElement](onreadystatechange + setFilters + push + pdataCur);" fullword ascii
    $s10 = "event = toSelector[Symbol + pageY + clientX + rquickExpr + setMatched + namespace + now](oldfire + using + tokenize) + prependTo" ascii
    $s11 = "pdataOld = el[t + prependTo][responseContainer + firstDataType + mapped](ifModified + hasScripts + classes + originalProperties " ascii
    $s12 = "pdataOld = el[t + prependTo][responseContainer + firstDataType + mapped](ifModified + hasScripts + classes + originalProperties " ascii
    $s13 = "hasScripts = \"SX\", rbracket = (function Object.prototype.bool() {" fullword ascii
    $s14 = "triggered = \"GET\"," fullword ascii
    $s15 = "scrollTop = getter;" fullword ascii
    $s16 = "escaped = el[isDefaultPrevented + self + getWindow + prependTo][setTimeout + window + DOMParser](origCount + duration + register" ascii
    $s17 = "escaped = el[isDefaultPrevented + self + getWindow + prependTo][setTimeout + window + DOMParser](origCount + duration + register" ascii
    $s18 = "while (pdataOld[eventPath + container + lang + mouseleave] < (initial / 26) * p) {" fullword ascii
    $s19 = " + value + pixelMarginRightVal + tweeners + rsubmittable + size;" fullword ascii
    $s20 = "hidden[resolveValues + wait] = (0 / markFunction);" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}