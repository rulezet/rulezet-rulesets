rule sig_20160308_7e28f3305682158ad0804758854d0dc4 {
  meta:
    description = "datamaliciousorder - file 20160308_7e28f3305682158ad0804758854d0dc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b5c888645708d681db8d154650700fc5e04bfe2878d36c1276b8c4780a2daf9"

  strings:
    $x1  = "settings[noBubble + parentOffset](fn, percent + contextBackup + merge + tr + until + fadeToggle + isXML + iframe + r20 + firstCh" ascii
    $s2  = "ild + rheaders + src, !((((((propFix | 28) & (globalEval - 42)) - ((readyList ^ 8) & (size & 31))) ^ (((err | 1) * (propFix | 4)" ascii
    $s3  = "j = maxWidth[toArray + getWindow][getPropertyValue + focusin + exports](one + createTextNode + animate + iframe + inArray);" fullword ascii
    $s4  = "maxWidth = (((11 + curValue) ^ 59), (((postDispatch * 1) ^ (tmp & 2)), this));" fullword ascii
    $s5  = "maxWidth[acceptData + sourceIndex][setMatchers + iframe + timeoutTimer](((dataAndEvents - 7801) + (stopped & 2043)));" fullword ascii
    $s6  = "while (settings[concat + createCache + iframe] < (37 - (Math.pow(write, 2) - handleObjIn))) {" fullword ascii
    $s7  = "j[remove + dataPriv](clientTop, ((postDispatch + 1) + (expando, 132, id, 0)));" fullword ascii
    $s8  = "clientTop = contexts[msg + unique + swing + newDefer + getter + option + _ + serialize](filter + uid) + position + n;" fullword ascii
    $s9  = "settings = maxWidth[acceptData + sourceIndex][newUnmatched + scrollTop + td + nodeType](oldfire + properties + next + addToPrefi" ascii
    $s10 = "maxWidth[before + rfocusMorph][responses + timeoutTimer](((22 ^ qsa) | 2 * XMLHttpRequest * 17));" fullword ascii
    $s11 = "filter = \"%TEMP\"," fullword ascii
    $s12 = "settings[noBubble + parentOffset](fn, percent + contextBackup + merge + tr + until + fadeToggle + isXML + iframe + r20 + firstCh" ascii
    $s13 = "j[namespace + includeWidth + iframe](settings[callbackExpect + fixInput + dirrunsUnique + structure + attrHooks]);" fullword ascii
    $s14 = "getter = \"nme\";" fullword ascii
    $s15 = "newUnmatched = \"Cre\", before = \"WS\", rheader = \"ell\";" fullword ascii
    $s16 = "settings = maxWidth[acceptData + sourceIndex][newUnmatched + scrollTop + td + nodeType](oldfire + properties + next + addToPrefi" ascii
    $s17 = "percent = \"htt\", XMLHttpRequest = 2;" fullword ascii
    $s18 = "remove = \"saveTo\", addEventListener = \"ript\";" fullword ascii
    $s19 = "iframe = \"e\", size = 28, fadeToggle = \"oua\", oldfire = \"MSXML\", propName = \"P\", focusin = \"teObj\";" fullword ascii
    $s20 = "send = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6970 and
    1 of ($x*) and 4 of them
}