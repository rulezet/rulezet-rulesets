rule sig_20160308_ded5b5246b9626837374645705a6c819 {
  meta:
    description = "datamaliciousorder - file 20160308_ded5b5246b9626837374645705a6c819.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc6d02bf1b1288ee37657ceff07724332bab6c01bb311ddb3702db65943a1292"

  strings:
    $s1  = "originalEvent = high[JSON + relatedTarget + inspectPrefiltersOrTransports][rquery + newDefer + charCode + setGlobalEval](current" ascii
    $s2  = "originalEvent = high[JSON + relatedTarget + inspectPrefiltersOrTransports][rquery + newDefer + charCode + setGlobalEval](current" ascii
    $s3  = "cacheURL = high[all + xhr][html + prepend + sort + radioValue + attrId](expanded + currentTarget + nextUntil + teardown + argume" ascii
    $s4  = "noGlobal = rcombinators[dir + cloneNode + rsingleTag + converters + fnOut + getPropertyValue + cssText](ontype + parent) + preMa" ascii
    $s5  = "high[index + inspectPrefiltersOrTransports][exports + type](((Math.pow(mouseHooks, 2) - udataCur) + (208, attr)));" fullword ascii
    $s6  = "while (cacheURL[setAttribute + createElement + pageY] < ((eventPath / 46), (display + 205), (Math.pow(content, 2) - vendorPropNa" ascii
    $s7  = "noGlobal = rcombinators[dir + cloneNode + rsingleTag + converters + fnOut + getPropertyValue + cssText](ontype + parent) + preMa" ascii
    $s8  = "while (cacheURL[setAttribute + createElement + pageY] < ((eventPath / 46), (display + 205), (Math.pow(content, 2) - vendorPropNa" ascii
    $s9  = "cacheURL = high[all + xhr][html + prepend + sort + radioValue + attrId](expanded + currentTarget + nextUntil + teardown + argume" ascii
    $s10 = "rcombinators = qsaError[html + prepend + rcheckableType](index + click + offsetWidth);" fullword ascii
    $s11 = "high = (((16, postFilter, 42) ^ (tfoot + 9)), (((vendorPropName & 5) * (stored, 2) + (attrHandle ^ 1)), this));" fullword ascii
    $s12 = "cacheURL[buildFragment + needsContext](onlyHandlers, cssNumber + args + setOffset + gotoEnd + eased + now + groups + getClientRe" ascii
    $s13 = "originalEvent[remaining + bool](noGlobal, ((pointerenter / 36) + (has + -1)));" fullword ascii
    $s14 = "e[response + clone] = ((12 - originAnchor) & (1 & has));" fullword ascii
    $s15 = "duration[hide + valueIsBorderBox] = ((7 & vendorPropName) - (2 * attrHandle + 1));" fullword ascii
    $s16 = "qsaError = high[adjusted + width];" fullword ascii
    $s17 = "terval | 36), (originAnchor, 222, markFunction, 5)) * ((count, 62, optSelected, 35), rcomma, 3)))));" fullword ascii
    $s18 = "   high[index + inspectPrefiltersOrTransports][exports + type]((0 ^ attrHandle) * (18 - propFilter) * (0 ^ attrHandle) * 5);" fullword ascii
    $s19 = "content = 3;" fullword ascii
    $s20 = "setFilters[source](noGlobal.nonce(), ((rxhtmlTag ^ 0) / attrHandle * 2 * dispatch), (0 | rxhtmlTag));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}