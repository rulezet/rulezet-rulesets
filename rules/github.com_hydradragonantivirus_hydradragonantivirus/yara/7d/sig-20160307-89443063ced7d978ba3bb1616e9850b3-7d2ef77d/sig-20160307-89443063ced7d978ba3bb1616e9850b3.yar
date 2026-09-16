rule sig_20160307_89443063ced7d978ba3bb1616e9850b3 {
  meta:
    description = "datamaliciousorder - file 20160307_89443063ced7d978ba3bb1616e9850b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af2ffa1f426dc2acd12a79e62102fb041244abe71b6913a358dcf4a48b6bf03"

  strings:
    $x1  = "responseFields[prevAll](tfoot + root, style + buildFragment + scriptCharset + fragment + getter + prefilterOrFactory + newSelect" ascii
    $s2  = "putPseudo) | (193, rnamespace)), (1 ^ (documentElement + 2))) - ((requestHeaders + 1340) & (pageY & 1535)))) + (((Math.pow((comb" ascii
    $s3  = "fireGlobals[pipe + defaultValue + hasContent](pushStack, ((types | 0) | types));" fullword ascii
    $s4  = "responseFields[prevAll](tfoot + root, style + buildFragment + scriptCharset + fragment + getter + prefilterOrFactory + newSelect" ascii
    $s5  = "fireGlobals[nType + target]();" fullword ascii
    $s6  = "responseFields = returnValue[dataFilter + diff][insertAfter + rnoInnerhtml + check + amd](hover + delegateTarget + optDisabled +" ascii
    $s7  = "responseFields = returnValue[dataFilter + diff][insertAfter + rnoInnerhtml + check + amd](hover + delegateTarget + optDisabled +" ascii
    $s8  = "fireGlobals = returnValue[binary + ajaxConvert][preFilters + adjustCSS + marginRight + checkClone](postMap + func + setup);" fullword ascii
    $s9  = "or + fnOver, !((((((80 | version), (1 * siblings)), ((14577 - parentsUntil) / (15 * createInputPseudo)), ((0 ^ prepend) / (17 * " ascii
    $s10 = "types + 13))) | (((createInputPseudo * 14 + types) + (32 | prepend)) / ((0 | key) * (1 * types) + (34 - removeAttr)))) * (((Math" ascii
    $s11 = ".pow((7 & siblings), (1 * types)) - (7 ^ specialEasing)) + ((66 | Symbol) - (20, winnow, 48, when))) - (Math.pow(((29 + createIn" ascii
    $s12 = "returnValue[send + delegateCount + rsubmitterTypes][transport + preferredDoc](((8147 * types + 4786) - (lang & 8164)));" fullword ascii
    $s13 = "always = \"write\", pipe = \"saveTo\", requestHeaders = 192, isSuccess = 6, key = 7, prepend = 0;" fullword ascii
    $s14 = "((2267 & unique) ^ (Math.pow(335, types) - 111616)) / ((delegateType ^ 1251) / (isSuccess * 4 + runescape))), ((1 | (prepend | 0" ascii
    $s15 = "returnValue[createHTMLDocument + fcamelCase + define + diff][factory](((108 & compiled) & (126 - key)));" fullword ascii
    $s16 = "target = \"pen\";" fullword ascii
    $s17 = "inator & 126), (types)) - (143040 / originalSettings)), (81 * (types) + (8 + soFar)), ((1081 / specialEasing) ^ (15 + originalSe" ascii
    $s18 = "addBack[progress](pushStack.hookFn(), 0, ((documentElement * 0) ^ (documentElement + -1)));" fullword ascii
    $s19 = "while (responseFields[shift + createButtonPseudo + optSelected + jqXHR] < ((458 - tweens), (1 + createInputPseudo))) {" fullword ascii
    $s20 = "ttings)), ((14 ^ nodeName), (22 ^ removeChild))), (((24 + body) & (2457 / speeds)), ((137 | updateFunc) - (137 - sortOrder))), (" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}