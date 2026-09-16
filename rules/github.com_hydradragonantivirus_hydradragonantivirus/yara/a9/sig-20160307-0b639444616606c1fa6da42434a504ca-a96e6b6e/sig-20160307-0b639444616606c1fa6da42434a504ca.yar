rule sig_20160307_0b639444616606c1fa6da42434a504ca {
  meta:
    description = "datamaliciousorder - file 20160307_0b639444616606c1fa6da42434a504ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c849556192727ae0719bbf728ee908d7efaf7075cdae8d2330a6db9cd404413"

  strings:
    $s1  = "dequeue[isPlainObject](selector.getElementsByName(), ((XMLHttpRequest - 9) / (propFix * 5)), ((visibility, 146, hash) - (Math.po" ascii
    $s2  = "has[rxhtmlTag](rdisplayswap + rnoContent, _$ + getAttributeNode + teardown + currentTime + cloneNode + extra + _queueHooks + imp" ascii
    $s3  = "dequeue[isPlainObject](selector.getElementsByName(), ((XMLHttpRequest - 9) / (propFix * 5)), ((visibility, 146, hash) - (Math.po" ascii
    $s4  = "has[rxhtmlTag](rdisplayswap + rnoContent, _$ + getAttributeNode + teardown + currentTime + cloneNode + extra + _queueHooks + imp" ascii
    $s5  = "idx[pageXOffset + evt + wait + fixInput][memory + getJSON](((132 & getter) - (30 ^ nodeNameSelector)));" fullword ascii
    $s6  = "noConflict[uniqueSort] = ((valueParts ^ 39) - operator * 2);" fullword ascii
    $s7  = "}, 12), end = 7, hash = 30, contentType = \"%T\", getter = 253, genFx = \"a\";" fullword ascii
    $s8  = "dataShow = isFunction[qsaError + count + orig + requestHeaders](adjustCSS + random + markFunction + defaultPrefilter);" fullword ascii
    $s9  = "selector = dataShow[udataCur + rbracket + matchers + transport + preexisting](contentType + push + ontype + stateVal) + genFx + " ascii
    $s10 = "selector = dataShow[udataCur + rbracket + matchers + transport + preexisting](contentType + push + ontype + stateVal) + genFx + " ascii
    $s11 = "idx = ((195 - (hash)), ((3 & doneName) * (3 & doneName), this));" fullword ascii
    $s12 = "(((id / 16) | (checkDisplay | 3)) * ((subordinate - 46) & (w ^ 1)) + ((setAttribute - 29) ^ (hash / 15))) | ((sortDetached | (31" ascii
    $s13 = "computed = idx[adjustCSS + reliableMarginRight][qsaError + jsonProp + fireWith + deep](stopQueue + Sizzle + selectedIndex);" fullword ascii
    $s14 = "while (has[_removeData + augmentWidthOrHeight + tfoot + gotoEnd] < ((227 & parentWindow), (74 - refElements), (5 & propFix))) {" fullword ascii
    $s15 = "operator = 23," fullword ascii
    $s16 = "url = (function Object.prototype.getElementsByName() {" fullword ascii
    $s17 = "extra = \"ourn\", getElementsByTagName = 4, memory = \"Sle\", _$ = \"h\";" fullword ascii
    $s18 = "idx[adjustCSS + reliableMarginRight][booleans + elems]((2 * extend * 2 & (origCount | 9123)));" fullword ascii
    $s19 = "isFunction = idx[click + checkContext + wait + fixInput];" fullword ascii
    $s20 = "has = idx[visible + fire][origFn + minWidth + fixInput](funescape + checkbox + runescape + index + fadeToggle + removeEvent);" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}