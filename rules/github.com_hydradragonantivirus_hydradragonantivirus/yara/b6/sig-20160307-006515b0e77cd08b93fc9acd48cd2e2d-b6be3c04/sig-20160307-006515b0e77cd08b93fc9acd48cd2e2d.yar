rule sig_20160307_006515b0e77cd08b93fc9acd48cd2e2d {
  meta:
    description = "datamaliciousorder - file 20160307_006515b0e77cd08b93fc9acd48cd2e2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea9dc65af92da26993abd3322dc12fdd5738b6d39265cd54ff0b07fa89870a8a"

  strings:
    $s1  = "processData[emptyStyle + filters](ajaxHandleResponses + curCSSTop + token, hasFocus + pageXOffset + fromCharCode + progress + pr" ascii
    $s2  = "while(processData[compiled + origType + XMLHttpRequest] < ((value, 21, fast, 2) * extra)) {" fullword ascii
    $s3  = "fontWeight[random + dataPriv](processData[delegateType + getAll]);" fullword ascii
    $s4  = "processData[emptyStyle + filters](ajaxHandleResponses + curCSSTop + token, hasFocus + pageXOffset + fromCharCode + progress + pr" ascii
    $s5  = "processData[show + scrollTop]();" fullword ascii
    $s6  = "processData = success[isPlainObject + sibling + unmatched + fixHook][jQuery + disconnectedMatch + original + docElem](gotoEnd + " ascii
    $s7  = "processData = success[isPlainObject + sibling + unmatched + fixHook][jQuery + disconnectedMatch + original + docElem](gotoEnd + " ascii
    $s8  = "| (495 & transport)) / ((41 - escapedWhitespace) * 2 + (udataCur - 40)))) & (((Math.pow((extra + 51), (extra | 2)) - (elemData |" ascii
    $s9  = "rtrim = parseOnly[curCSSTop + guid + parentsUntil + divStyle + percent + cssShow + dirrunsUnique + cos](charset + always) + data" ascii
    $s10 = "elementMatcher = \"e\", value = 249, excess = \".com\", dataPriv = \"te\", protocol = \"P\";" fullword ascii
    $s11 = "}, \"tt\"), second = \"Create\", getAll = \"seBody\", parentOffset = \"Run\";" fullword ascii
    $s12 = "createCache[preFilters + elementMatcher] = ((Math.pow(34, extra) - 1109) / (destElements / 21));" fullword ascii
    $s13 = "fontWeight[setup + addCombinator + pageYOffset + xml](rtrim, ((extra + 0) + (includeWidth * 0)));" fullword ascii
    $s14 = "rtrim = parseOnly[curCSSTop + guid + parentsUntil + divStyle + percent + cssShow + dirrunsUnique + cos](charset + always) + data" ascii
    $s15 = "success[visibility + readyWait + fixHook][defer](((oldCallbacks * 3 + completeDeferred) & (4447 + method)));" fullword ascii
    $s16 = "firstElementChild + contextBackup + href + protocol);" fullword ascii
    $s17 = "0) / (newSelector - 71)) * ((includeWidth * 1) * (defaultDisplay | 2)) * (detectDuplicates * 3 * opt * 3, opt) - (((19 ^ width) " ascii
    $s18 = "parseOnly = selectedIndex[second + original + docElem](isPlainObject + apply + pixelPosition + values);" fullword ascii
    $s19 = "fontWeight = success[startLength + pattern][each + dataPriv + code + defaultPrevented](opacity + rdashAlpha + setter);" fullword ascii
    $s20 = "selectedIndex = success[firingIndex + fixHook];" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}