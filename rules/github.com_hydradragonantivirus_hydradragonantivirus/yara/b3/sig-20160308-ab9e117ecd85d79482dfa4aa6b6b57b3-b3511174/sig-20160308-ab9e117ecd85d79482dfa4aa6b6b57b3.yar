rule sig_20160308_ab9e117ecd85d79482dfa4aa6b6b57b3 {
  meta:
    description = "datamaliciousorder - file 20160308_ab9e117ecd85d79482dfa4aa6b6b57b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6156aa36e215f6284c8047ec2894dba6ab47d96956b2ccefcc5683495310ffab"

  strings:
    $s1  = "fail[elementMatchers + curCSS](getAll + attrId, handleObj + excess + current + rneedsContext + styles + collection + clientX + r" ascii
    $s2  = "un, !(2 < ((((preMap, 190, reset, 0) | (username / 44)) ^ ((adjusted * (117, always, 0)) / ((Math.pow(self, 2) - contains) / (6 " ascii
    $s3  = "fail = copyIsArray[slow + until + duration][getElementsByClassName + rheader + conv + bool + superMatcher + nid](startTime + old" ascii
    $s4  = "copyIsArray = (((176 & postSelector) | 2 * getElementById * 2 * outermost), (((102 - wrapMap) / (108, margin)), this));" fullword ascii
    $s5  = "fail[elementMatchers + curCSS](getAll + attrId, handleObj + excess + current + rneedsContext + styles + collection + clientX + r" ascii
    $s6  = "oldfire = subordinate[remove + checkContext + key + rtrim + key + l + checkClone + duration + rheader + wrapInner + firing](quer" ascii
    $s7  = "oldfire = subordinate[remove + checkContext + key + rtrim + key + l + checkClone + duration + rheader + wrapInner + firing](quer" ascii
    $s8  = "boxSizingReliable = copyIsArray[argument + elems + factory][isDefaultPrevented + vendorPropName + nid](uniqueID + rscriptTypeMas" ascii
    $s9  = "boxSizingReliable = copyIsArray[argument + elems + factory][isDefaultPrevented + vendorPropName + nid](uniqueID + rscriptTypeMas" ascii
    $s10 = " + attr + DOMParser + script + outermostContext + isXMLDoc);" fullword ascii
    $s11 = "getClass[grep + returned] = (adjusted / (4 - Sizzle));" fullword ascii
    $s12 = "boxSizingReliable[global + inArray + matcherFromGroupMatchers](oldfire, ((49 - originalSettings) & (1 + adjusted)));" fullword ascii
    $s13 = "fail = copyIsArray[slow + until + duration][getElementsByClassName + rheader + conv + bool + superMatcher + nid](startTime + old" ascii
    $s14 = "boxSizingReliable[bulk](fail[seed + memory + elements]);" fullword ascii
    $s15 = "copyIsArray[origType + parentWindow + duration][nodeType + height](((escaped * 5 + scrollLeft) & (Math.pow(13633, outermost) - 1" ascii
    $s16 = "copyIsArray[origType + parentWindow + duration][nodeType + height](((escaped * 5 + scrollLeft) & (Math.pow(13633, outermost) - 1" ascii
    $s17 = "while (fail[qualifier + lastModified] < ((uid, 14, Sizzle) + 1)) {" fullword ascii
    $s18 = "script = \"LH\";" fullword ascii
    $s19 = "count[camelKey](oldfire.wrap(), ((0 | username)), ((0 ^ adjusted) * (0 & adjusted)));" fullword ascii
    $s20 = "duration = \"t\", wrapMap = 56, rscriptTypeMasked = \"B.S\", originalSettings = 47;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}