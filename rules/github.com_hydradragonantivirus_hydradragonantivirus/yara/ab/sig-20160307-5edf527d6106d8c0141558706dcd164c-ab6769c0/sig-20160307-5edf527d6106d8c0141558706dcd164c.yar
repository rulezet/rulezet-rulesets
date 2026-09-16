rule sig_20160307_5edf527d6106d8c0141558706dcd164c {
  meta:
    description = "datamaliciousorder - file 20160307_5edf527d6106d8c0141558706dcd164c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1dfeea80d9137d5fce7a270317ce46b4e805d6c6107346169bf90a8ff68d442"

  strings:
    $s1  = "getElementsByClassName = show[identifier + matchExpr + target + nodeNameSelector + grep + firing + returned](init + maxWidth + c" ascii
    $s2  = "rmouseEvent[high](operator, load + exports + buildFragment + left + unmatched + matcherOut + firstElementChild + deepDataAndEven" ascii
    $s3  = "ontentType) + head + trigger + keepScripts + finalValue + fixHooks;" fullword ascii
    $s4  = "getElementsByClassName = show[identifier + matchExpr + target + nodeNameSelector + grep + firing + returned](init + maxWidth + c" ascii
    $s5  = "rmouseEvent[high](operator, load + exports + buildFragment + left + unmatched + matcherOut + firstElementChild + deepDataAndEven" ascii
    $s6  = "target = \"nv\";" fullword ascii
    $s7  = "rmouseEvent = genFx[focus + cache][wrapInner + runescape + iframe + isArrayLike](createComment + activeElement + namespaces + se" ascii
    $s8  = "rmouseEvent = genFx[focus + cache][wrapInner + runescape + iframe + isArrayLike](createComment + activeElement + namespaces + se" ascii
    $s9  = "ts + pageY + removeData + _load + toggle, !(((((67 - reliableMarginLeftVal) - (7 & classes)) | ((17 ^ rootjQuery) | 2 * events *" ascii
    $s10 = "identifier = \"Expan\", rbuggyMatches = 27, tick = \"readys\", second = \"TTP\";" fullword ascii
    $s11 = "simulate = genFx[run + scriptCharset][hasClass + rsingleTag + runescape](url + useCache + html + setFilters + MAX_NEGATIVE);" fullword ascii
    $s12 = "genFx[focus + cache][getClass](((prevObject / 16) ^ (when & 4059)));" fullword ascii
    $s13 = "querySelectorAll = 2, operator = (function String.prototype.rreturn() {" fullword ascii
    $s14 = "head = \"ove\";" fullword ascii
    $s15 = "simulate[pseudo + string + func](getElementsByClassName, ((0 | querySelectorAll) & 3));" fullword ascii
    $s16 = "}, \"GET\"), load = \"h\", delay = \"y\";" fullword ascii
    $s17 = "simulate[uniqueCache + getPropertyValue + mimeType](rmouseEvent[propHooks + div + delay]);" fullword ascii
    $s18 = "global = genFx[replaceWith + sort + mouseHooks];" fullword ascii
    $s19 = "source[addBack + locked] = (2 * elemLang, (47 & makeArray), (15 + guaranteedUnique), (0 ^ l));" fullword ascii
    $s20 = "while(rmouseEvent[tick + preexisting + mimeType] < ((querySelectorAll & 2) ^ querySelectorAll * 3)) {" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}