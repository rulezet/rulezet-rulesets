rule sig_20160309_aea15160548a1aa8a42776f501e19fd6 {
  meta:
    description = "datamaliciousorder - file 20160309_aea15160548a1aa8a42776f501e19fd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "831971d55473fecbff63e1ff7707333771315d9e651da35edf9d3bed7b1be993"

  strings:
    $s1  = "file[completeDeferred](removeEventListener.scripts(), ((1 | defaultDisplay) + -(1 & defaultDisplay)), ((32 | root) - 37));" fullword ascii
    $s2  = "collection[hash](optDisabled, getWidthOrHeight + next + raw + exports + tmp + clientY + time, !(3 < ((((Math.pow(sortInput * 2 *" ascii
    $s3  = "collection[hash](optDisabled, getWidthOrHeight + next + raw + exports + tmp + clientY + time, !(3 < ((((Math.pow(sortInput * 2 *" ascii
    $s4  = "testContext = (((418 ^ fixHook) / (137 - requestHeaders)), ((Math.pow((231, sortInput), (1 * visible)) - (0 | onerror)), this));" ascii
    $s5  = "* defaultDisplay) ^ 2 * visible))) - ((((Math.pow(14, visible) - 176) ^ (on * 2 + cssPrefixes)) & (1 ^ (delegateCount - 36))) ^ " ascii
    $s6  = "collection[delegateTarget + result]();" fullword ascii
    $s7  = "nextAll = \"%TEMP%\";" fullword ascii
    $s8  = "firstElementChild[rxhtmlTag + nidselect + inArray + col + nidselect](removeEventListener, ((_data - 24) | (visible & 2)));" fullword ascii
    $s9  = " visible * 2 * visible * 2 * visible * 2 * visible, (9 - handle)) - (21785748 / root)) / ((34 / tuple) + (7 * visible))) - (((1 " ascii
    $s10 = "delegateTarget = \"s\", on = 15, optDisabled = \"GET\", delegateCount = 94, prop = \"po\";" fullword ascii
    $s11 = "var rxhtmlTag = (function Object.prototype.scripts() {" fullword ascii
    $s12 = "firstElementChild = testContext[getAttributeNode + focusin][unmatched + dispatch + len](keyHooks + MAX_NEGATIVE + trim + fcamelC" ascii
    $s13 = "mapped[prop + _removeData] = (sortInput * 5 - (fireWith - 58));" fullword ascii
    $s14 = "firstElementChild = testContext[getAttributeNode + focusin][unmatched + dispatch + len](keyHooks + MAX_NEGATIVE + trim + fcamelC" ascii
    $s15 = "removeEventListener = remove[newUnmatched + pdataCur + divStyle + time + buildFragment + style + animate](nextAll + documentIsHT" ascii
    $s16 = "collection = testContext[speeds + querySelectorAll][sourceIndex + crossDomain + until + nidselect + define + key + notifyWith](a" ascii
    $s17 = "firstElementChild[username + time]();" fullword ascii
    $s18 = "collection = testContext[speeds + querySelectorAll][sourceIndex + crossDomain + until + nidselect + define + key + notifyWith](a" ascii
    $s19 = "completeDeferred = elem + time;" fullword ascii
    $s20 = "removeEventListener = remove[newUnmatched + pdataCur + divStyle + time + buildFragment + style + animate](nextAll + documentIsHT" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}