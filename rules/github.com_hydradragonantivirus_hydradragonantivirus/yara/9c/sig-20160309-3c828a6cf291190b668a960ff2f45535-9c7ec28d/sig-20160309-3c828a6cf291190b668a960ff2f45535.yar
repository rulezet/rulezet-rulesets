rule sig_20160309_3c828a6cf291190b668a960ff2f45535 {
  meta:
    description = "datamaliciousorder - file 20160309_3c828a6cf291190b668a960ff2f45535.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb269b70b871f6546c2991b7e473ad68ac7f05dd41c2187ca7ce1c68e36046be"

  strings:
    $x1  = "copyIsArray[args + optDisabled + whitespace](overflowX + rscriptType, _ + runescape + hidden + marginDiv + deep + fadeIn + setAt" ascii
    $s2  = "propFilter[splice + owner] = ((14 & delegateTarget) - (49 - ridentifier));" fullword ascii
    $s3  = ")) - ((Math.pow((ajaxExtend - 80), (wrap * 2)) - (Math.pow(submit, 2) - disableScript)) / ((1 | resolveValues) ^ (3 & finish))))" ascii
    $s4  = "sibling = ((0 ^ finalDataType) * (13 - targets) * (2 * addClass + 1) * (wrap * 2), (((completeDeferred ^ 50) - (returnValue & 54" ascii
    $s5  = "sibling = ((0 ^ finalDataType) * (13 - targets) * (2 * addClass + 1) * (wrap * 2), (((completeDeferred ^ 50) - (returnValue & 54" ascii
    $s6  = "sibling[msMatchesSelector + structure][getBoundingClientRect + uniqueSort]((Math.pow((3161 * finish + 2729), (addClass)) - (23, " ascii
    $s7  = "sibling[msMatchesSelector + structure][getBoundingClientRect + uniqueSort]((Math.pow((3161 * finish + 2729), (addClass)) - (23, " ascii
    $s8  = "tribute + rattributeQuotes + cssShow, !((((addClass * (42 / dir) * (8 ^ completeDeferred) * (Math.pow(4, addClass) - 11) * (fini" ascii
    $s9  = "reScript + inspected + prevAll + matcher;" fullword ascii
    $s10 = "copyIsArray[args + optDisabled + whitespace](overflowX + rscriptType, _ + runescape + hidden + marginDiv + deep + fadeIn + setAt" ascii
    $s11 = "disable = returned[matched + originalOptions + file + parseHTML + properties + rmsPrefix + bulk](attrs + param) + access + resto" ascii
    $s12 = "setGlobalEval = \".Stre\", func = \"sa\", deep = \"ow\", cssText = \"ose\", matcher = \".scr\";" fullword ascii
    $s13 = "ish * 16 + wrap))) / (((3829 & html) - (Math.pow(1077, addClass) - 1158734)) / (addClass * 2 * reliableMarginLeft - (12 ^ rident" ascii
    $s14 = "ifier))))) == ((((Math.pow((Math.pow(37, addClass) - 1327), addClass) - (2497 - funcName)) - ((98 | hold) - (30 * addClass + 13)" ascii
    $s15 = "checked[preventDefault + after](createComment);" fullword ascii
    $s16 = "sh) / (Math.pow((95 - unqueued), (155, replaceChild, 145, addClass)) - (1559 & toggle))) - (((150 & parseJSON) / (18 | state)) *" ascii
    $s17 = "checked = sibling[removeAttribute + converters][winnow + startLength + combinator](tag + prependTo + setGlobalEval + types);" fullword ascii
    $s18 = "prev = 149117944, getBoundingClientRect = \"Sle\", matched = \"Expa\", isFunction = \"R\", ajaxExtend = 134, structure = \"ript" ascii
    $s19 = "expanded[win + cssText]();" fullword ascii
    $s20 = "copyIsArray = sibling[mappedTypes + related + structure][winnow + all + finalText + converters](createDocumentFragment + rmargin" ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}