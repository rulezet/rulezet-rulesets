rule sig_20160308_bd8099761a58737d51ada2221c64def0 {
  meta:
    description = "datamaliciousorder - file 20160308_bd8099761a58737d51ada2221c64def0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bfcd2eddfff13872aaba3304f5d930f7f0982b8acd70acbbf15c2952e5c6722"

  strings:
    $x1  = "subordinate[then](contexts + onreadystatechange, appendTo + src + createOptions + rnotwhite + nonce + newContext + nextUntil + f" ascii
    $x2  = "Doc))) - (2 * (adown * 2))) - (((getScript | 224), (adjusted | 193), (base * 11 + rkeyEvent)), ((Math.pow(7, isXMLDoc) - 39) * u" ascii
    $s3  = "overrideMimeType[getter + random + find][documentIsHTML + dataShow](((rscriptTypeMasked + 6925) & (diff / 43)));" fullword ascii
    $s4  = "hide = overrideMimeType[password + idx][rmargin + onlyHandlers + curValue + removeAttribute + href](guid + stateVal + fns + sele" ascii
    $s5  = "hide = overrideMimeType[password + idx][rmargin + onlyHandlers + curValue + removeAttribute + href](guid + stateVal + fns + sele" ascii
    $s6  = "  overrideMimeType[cssNormalTransform + swap][slideDown]((7 * username * 3 - (adown + 4)));" fullword ascii
    $s7  = "delegate = getAttribute[isTrigger + cssShow + random + selected + createFxNow + combinator + deepDataAndEvents](checkOn + keyHoo" ascii
    $s8  = "hide[ajaxExtend + isWindow + dataTypeOrTransport + cos + dataTypeOrTransport](delegate, ((match - 69) - username * 5));" fullword ascii
    $s9  = "while (subordinate[setRequestHeader + conv] < ((39 ^ dataTypeExpression) - (55 & time))) {" fullword ascii
    $s10 = "subordinate = overrideMimeType[cssNormalTransform + swap][ap + m + domManip + dataTypeOrTransport + pixelPosition](destElements " ascii
    $s11 = "subordinate = overrideMimeType[cssNormalTransform + swap][ap + m + domManip + dataTypeOrTransport + pixelPosition](destElements " ascii
    $s12 = "ail + isEmptyObject + rbracket, !((((adown ^ (1 + adown)) & (22 / fromCharCode)) + ((Math.pow(216, isXMLDoc) - 46436), (end | 64" ascii
    $s13 = "factory[run](delegate.fireGlobals(), ((propHooks | 0) & (adown ^ 0)), ((defaultPrevented * 5) - defaultPrevented * 5));" fullword ascii
    $s14 = "delegate = getAttribute[isTrigger + cssShow + random + selected + createFxNow + combinator + deepDataAndEvents](checkOn + keyHoo" ascii
    $s15 = "fadeIn = \"Resp\", fail = \"54g\", keyHooks = \"MP\", rtagName = \"ript\", dataShow = \"ep\", clearTimeout = \"Run\";" fullword ascii
    $s16 = "getAttribute = originalEvent[ap + returnValue + pixelPosition](cssNormalTransform + splice + defaultView + charCode);" fullword ascii
    $s17 = "parentOffset = \"positi\", isTrigger = \"Expand\", getElementById = \"write\", combinator = \"Strin\", cssNormalTransform = \"WS" ascii
    $s18 = "overrideMimeType = ((7 * isXMLDoc * 2 * isXMLDoc * 2 * isXMLDoc * 2 * isXMLDoc * 2 / (class2type / 37)), ((isXMLDoc * 2 * userna" ascii
    $s19 = "password = \"W\";" fullword ascii
    $s20 = "parentOffset = \"positi\", isTrigger = \"Expand\", getElementById = \"write\", combinator = \"Strin\", cssNormalTransform = \"WS" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}