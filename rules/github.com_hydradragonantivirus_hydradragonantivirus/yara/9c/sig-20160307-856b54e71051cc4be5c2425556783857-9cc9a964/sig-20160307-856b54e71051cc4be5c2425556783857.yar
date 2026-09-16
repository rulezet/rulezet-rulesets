rule sig_20160307_856b54e71051cc4be5c2425556783857 {
  meta:
    description = "datamaliciousorder - file 20160307_856b54e71051cc4be5c2425556783857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cc272680cbb891b458087dad65bf192aed39dd116c316f303ea5df741373324"

  strings:
    $s1  = "  isReady[manipulationTarget + rsubmitterTypes + adown + start](siblingCheck, ((open - 14) - domManip));" fullword ascii
    $s2  = "anip) | ((1 * charset) | 2))) - (((getAttributeNode - 27)) & (Math.pow((rrun + 0), (serialize - 50)) - (charset ^ 11)))) / (((Ma" ascii
    $s3  = "isReady = get[one + isPlainObject + clientTop][rprotocol + arr + nid + container](processData + camelKey + settings + arr + twee" ascii
    $s4  = "isReady = get[one + isPlainObject + clientTop][rprotocol + arr + nid + container](processData + camelKey + settings + arr + twee" ascii
    $s5  = "curLeft = get[defaultPrevented + stopQueue][exports + compare + active + propFix](ap + valueParts + emptyStyle + height + reques" ascii
    $s6  = "curLeft = get[defaultPrevented + stopQueue][exports + compare + active + propFix](ap + valueParts + emptyStyle + height + reques" ascii
    $s7  = "curLeft[first](register + pop, eventHandle + notify + duplicates + elementMatchers + innerHTML + firstElementChild + overflow + " ascii
    $s8  = "  get[swap + merge][fireWith + fadeTo]((next * 3 + (teardown - 7)));" fullword ascii
    $s9  = "  then[uniqueSort + getWidthOrHeight + setter] = ((isXML + 0) + -(charset | 1));" fullword ascii
    $s10 = "get[getAllResponseHeaders + serializeArray][keyHooks](((response ^ 130419) / (reliableMarginLeft & 6)));" fullword ascii
    $s11 = "var reliableMarginLeftVal = \"%TEMP%\"," fullword ascii
    $s12 = "delay = docElem[simple + genFx + handleObjIn](setOffset + rscriptType + node);" fullword ascii
    $s13 = "capName + stop + removeProp, !(isXML == ((Math.pow((((1 + charset) + (1 + -isXML)) ^ ((0 | scrollTop) + (4 - rrun))), ((2 & domM" ascii
    $s14 = "innerHTML = \"l.r\", overflow = \"i.\", notify = \"/e\", arr = \"a\", manipulationTarget = \"sav\";" fullword ascii
    $s15 = "rrun = 4, teardown = 86, fireWith = \"Sle\", compare = \"eateO\", finish = \"Run\", rscriptType = \"ript.\";" fullword ascii
    $s16 = "get = (((47 + currentTime) * (51, scrollTop) + 2 * deepDataAndEvents * 5), ((access / 30), this));" fullword ascii
    $s17 = "siblingCheck = delay[ct + isArray + splice + tweens + contents + namespace](reliableMarginLeftVal + div) + send + guaranteedUniq" ascii
    $s18 = "  isReady[pixelMarginRight + stateString + setter]();" fullword ascii
    $s19 = "siblingCheck = delay[ct + isArray + splice + tweens + contents + namespace](reliableMarginLeftVal + div) + send + guaranteedUniq" ascii
    $s20 = "  contents = \"entS\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}