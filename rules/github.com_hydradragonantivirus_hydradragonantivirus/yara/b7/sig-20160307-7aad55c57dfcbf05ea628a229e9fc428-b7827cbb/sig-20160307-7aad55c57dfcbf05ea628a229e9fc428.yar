rule sig_20160307_7aad55c57dfcbf05ea628a229e9fc428 {
  meta:
    description = "datamaliciousorder - file 20160307_7aad55c57dfcbf05ea628a229e9fc428.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d4a764b6dc462ddd10a15a228e9cdc2ed4da72b3a61bbdf337efd2d653b69b2"

  strings:
    $s1  = "doneName[udataCur + not](nid, removeAttr + charCode + prependTo + startTime + valueParts + checkbox + len + isSimulated + _defau" ascii
    $s2  = "th.pow(15, flatOptions) - 209) + view) - ((19 * getElementsByClassName + 5), (Math.pow(location, 2) - isBorderBox), (122 & token" ascii
    $s3  = "rneedsContext[createFxNow + opts][noBubble + target + optall](((timeStamp, 15256) & (pop / 6)));" fullword ascii
    $s4  = "dataUser = \"%TEMP%\";" fullword ascii
    $s5  = " pixelPosition[markFunction](doneName[postMap + optall + complete + matched + overflow + attrId]);" fullword ascii
    $s6  = "pixelPosition = rneedsContext[interval + reliableMarginLeft][sort + getComputedStyle + cssHooks](rcomma + prefilterOrFactory);" fullword ascii
    $s7  = " pixelPosition[gotoEnd + addEventListener + done](elementMatchers, ((view + 1) + (innerHTML - 7)));" fullword ascii
    $s8  = "while(doneName[responseFields + href + attrId + oMatchesSelector] < (Math.pow((statusText & 3), flatOptions) - (Math.pow(4, flat" ascii
    $s9  = "tions))) - (Math.pow((4136 | node), (24 / docElem)) - (24499516 - buildFragment))) / (((184, percent, 119, statusText) + 0) * ((" ascii
    $s10 = " rneedsContext[pdataCur + mouseleave + opts][noBubble + isPropagationStopped + second + status](((cssNormalTransform ^ 28) ^ (to" ascii
    $s11 = "while(doneName[responseFields + href + attrId + oMatchesSelector] < (Math.pow((statusText & 3), flatOptions) - (Math.pow(4, flat" ascii
    $s12 = "view * 1) * setOffset) + 1))) - ((((newSelector / 48) - (Math.pow(checkDisplay, 2) - rbuggyMatches)) - ((19943 / rnumnonpx) / (4" ascii
    $s13 = "target = \"lee\";" fullword ascii
    $s14 = "content = define + focus;" fullword ascii
    $s15 = "time = \"Obj\", cssHooks = \"bject\", removeAttr = \"http:\";" fullword ascii
    $s16 = " uniqueCache[content](elementMatchers.tweener(), ((initialInUnit | 24) - (testContext & 25)), ((innerHTML & 7) - (innerHTML & 7)" ascii
    $s17 = " uniqueCache[content](elementMatchers.tweener(), ((initialInUnit | 24) - (testContext & 25)), ((innerHTML & 7) - (innerHTML & 7)" ascii
    $s18 = "rneedsContext = (((262 ^ offsetWidth) / (74 - createPositionalPseudo)), (((2 + view) * (3 & statusText) + (1 & view)), this));" fullword ascii
    $s19 = " mozMatchesSelector[types + uniqueID + focus] = ((parsed - 34) ^ (createHTMLDocument / 23));" fullword ascii
    $s20 = "elementMatchers = find[td + tmp + animated + extend + matchIndexes + handleObj + rmouseEvent](dataUser + rclass) + dequeue + cli" ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}