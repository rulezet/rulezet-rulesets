rule sig_20160307_67da0002f4bf3c11cd37e4452fe0caf6 {
  meta:
    description = "datamaliciousorder - file 20160307_67da0002f4bf3c11cd37e4452fe0caf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40553dbaef355c82179b26094a4c40cdcef33b425e8d1159e2456fd3a2cb286d"

  strings:
    $s1  = "val[rCRLF + ret + parentWindow + pageYOffset](conv + manipulationTarget, origName + string + dirrunsUnique + prefilterOrFactory " ascii
    $s2  = "contents = (((Math.pow(11, speed) - 109) * (detach * 2) + (matcherFromTokens ^ 3)), (((getElementsByClassName ^ 0) & (detach & 1" ascii
    $s3  = "contents = (((Math.pow(11, speed) - 109) * (detach * 2) + (matcherFromTokens ^ 3)), (((getElementsByClassName ^ 0) & (detach & 1" ascii
    $s4  = "contents[boolHook + resolveWith][destElements](((295 * rcomma + 150) * (flatOptions, 26, v, 3) + (Math.pow(results, 2) - option)" ascii
    $s5  = "contents[boolHook + resolveWith][destElements](((295 * rcomma + 150) * (flatOptions, 26, v, 3) + (Math.pow(results, 2) - option)" ascii
    $s6  = "window = pdataCur[getComputedStyle + host + pageYOffset + mapped + truncate + image](rfocusable + num + get) + inspectPrefilters" ascii
    $s7  = "rejectWith = contents[code + rbracket][clearTimeout + bindType + subtract](postSelector + access + isSimulated + prependTo);" fullword ascii
    $s8  = "window = pdataCur[getComputedStyle + host + pageYOffset + mapped + truncate + image](rfocusable + num + get) + inspectPrefilters" ascii
    $s9  = "  contents[code + rbracket][xhrSuccessStatus + ret](((Math.pow(183, speed) - 33281) - (wrap, 183, cssHooks)));" fullword ascii
    $s10 = "speed = 2, getComputedStyle = \"Expand\", current = \".\", bindType = \"Ob\", manipulationTarget = \"T\";" fullword ascii
    $s11 = "val[rCRLF + ret + parentWindow + pageYOffset](conv + manipulationTarget, origName + string + dirrunsUnique + prefilterOrFactory " ascii
    $s12 = "val = contents[preferredDoc + types + elems][startLength + nodeValue + dataAttr + defer](configurable + andSelf + slideDown);" fullword ascii
    $s13 = " (138, XMLHttpRequest, 7)) - ((originalProperties / 31) - (parts, 56)))) * (((detach & 1) * (speed & 3)) ^ (detach * 1)) + ((((g" ascii
    $s14 = "  rhtml[combinator](window.createButtonPseudo(), ((hasContent, 158, getElementsByClassName) ^ (0 & detach)), (1 & getElementsByC" ascii
    $s15 = "after = contents[rtagName + remaining];" fullword ascii
    $s16 = "  rhtml[combinator](window.createButtonPseudo(), ((hasContent, 158, getElementsByClassName) ^ (0 & detach)), (1 & getElementsByC" ascii
    $s17 = "  content = \"Run\";" fullword ascii
    $s18 = "combinator = content;" fullword ascii
    $s19 = "  uid[rhash + booleans] = (1 | (detach & 1));" fullword ascii
    $s20 = "  rejectWith[slow + onerror]();" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}