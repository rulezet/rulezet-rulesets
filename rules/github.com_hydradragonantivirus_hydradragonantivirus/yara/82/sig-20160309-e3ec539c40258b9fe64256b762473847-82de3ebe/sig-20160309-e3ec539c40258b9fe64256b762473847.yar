rule sig_20160309_e3ec539c40258b9fe64256b762473847 {
  meta:
    description = "datamaliciousorder - file 20160309_e3ec539c40258b9fe64256b762473847.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7c7d518c7f95c991eaf028403ea4c9de27a74c44b9323c34c686770609dcfc4"

  strings:
    $s1  = "colgroup[requestHeaders](_load + emptyStyle, curCSS + state + handle + guid + rtagName + clone + round + access + triggerHandler" ascii
    $s2  = "getScript = reliableMarginRight[notifyWith + open + flatOptions + showHide + state](keyCode + target + createFxNow + msg);" fullword ascii
    $s3  = "hash[preferredDoc](ajaxPrefilter.optgroup(), ((38 - parseHTML) ^ (15, getAttributeNode)), ((0 | getAttributeNode) ^ (0 ^ getAttr" ascii
    $s4  = "hash[preferredDoc](ajaxPrefilter.optgroup(), ((38 - parseHTML) ^ (15, getAttributeNode)), ((0 | getAttributeNode) ^ (0 ^ getAttr" ascii
    $s5  = "hash = getScript;" fullword ascii
    $s6  = "hasDuplicate = jqXHR[keyCode + isHidden + state][step + keys + defaultPrefilter](targets + rbuggyMatches);" fullword ascii
    $s7  = "ajaxPrefilter = getScript[pageYOffset + dataShow + classes + setMatched + checkOn + matchExpr + base + list](using + curValue + " ascii
    $s8  = "jqXHR = (((561 / swing) + (6 + identifier)), (((81 - PI) | (7 ^ rjsonp)), this));" fullword ascii
    $s9  = "ajaxPrefilter = getScript[pageYOffset + dataShow + classes + setMatched + checkOn + matchExpr + base + list](using + curValue + " ascii
    $s10 = "oMatchesSelector = \"od\", target = \"cri\", ontype = \"bject\";" fullword ascii
    $s11 = "delegateTarget = colgroup[check + emptyGet + callbackExpect + oMatchesSelector + access];" fullword ascii
    $s12 = "blur[conditionFn + always] = (1 * getAttributeNode);" fullword ascii
    $s13 = "colgroup[requestHeaders](_load + emptyStyle, curCSS + state + handle + guid + rtagName + clone + round + access + triggerHandler" ascii
    $s14 = "tType + 0)), ((border * 2 + reject) / (1 ^ whitespace))) / (((350 / oldfire) + (1950 / overflowX)) - ((35 / oldfire) + (8 * stat" ascii
    $s15 = "hasDuplicate[complete + hasFocus + opacity](ajaxPrefilter, (2 + getAttributeNode));" fullword ascii
    $s16 = "dataPriv[originalEvent] = (getAttributeNode | (1 & identifier));" fullword ascii
    $s17 = "jqXHR[noCloneChecked + state][uid + preFilters](((2048 ^ dataTypeOrTransport) ^ (14128 & converters)));" fullword ascii
    $s18 = " + matcherFromGroupMatchers + isReady + htmlPrefilter + duplicates + docElem, !((((1 & identifier) * (1 & identifier)) ^ ((((Mat" ascii
    $s19 = "triggerHandler = \"st\", wait = \"TTP\", rtagName = \"ri-\", set = \"s\", getElementsByName = \"end\", getAttribute = \"writ\";" fullword ascii
    $s20 = "reliableMarginRight = jqXHR[nextUntil + JSON + state];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}