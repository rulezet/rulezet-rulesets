rule sig_20160308_544c4f677d4907c20c5b2f50287597fe {
  meta:
    description = "datamaliciousorder - file 20160308_544c4f677d4907c20c5b2f50287597fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "030d2582bc695483e3ff3efa4c0e616ec7d3d3e5098051bd14b6c8f8a7713059"

  strings:
    $s1  = "css[curCSSTop + original + seekingTransport + completed](disableScript, (filters + (1 + -status)));" fullword ascii
    $s2  = "caption[getBoundingClientRect](disableScript._removeData(), ((98, parts, 0) & (status & 1)), ((tmp - 29) / (eventPath | 50)));" fullword ascii
    $s3  = ".pow(postFilter, 2) - removeData), (Math.pow(161, filters) - 25731), (newSelector | 1)) * ((trim, 160, pos, 69) / (whitespace - " ascii
    $s4  = "not[namespace + firing](uniqueSort, matchAnyContext + attrNames + camel + a + outermostContext + focusin + tick + click + Sizzle" ascii
    $s5  = "while (not[eventDoc + marginDiv + onerror + write] < ((51 - isArray) | 0)) {" fullword ascii
    $s6  = "69)))) * (((cloneNode, 2) * (filters) * (Math.pow(20, filters) - 371) - (serialize & 15)) / ((matcher + 50) / (filters * 4)) * (" ascii
    $s7  = "actualDisplay[val + MAX_NEGATIVE + checked][computed + high + dataTypes + createTween](((tokenize / 19) + (select + 695)));" fullword ascii
    $s8  = "not = actualDisplay[cssNumber + parseOnly][list + rcombinators + onreadystatechange](complete + rts + charCode + setFilters);" fullword ascii
    $s9  = "disableScript = emptyStyle[speed + curOffset + isLocal + run + doc + firing + calculatePosition](argument + pnum + rejectWith) +" ascii
    $s10 = "disableScript = emptyStyle[speed + curOffset + isLocal + run + doc + firing + calculatePosition](argument + pnum + rejectWith) +" ascii
    $s11 = "preMap = actualDisplay[tabIndex + sibling + parseOnly];" fullword ascii
    $s12 = "css = actualDisplay[tabIndex + duplicates + adown + matcherIn + parseOnly][andSelf + subtract + pipe + specialEasing](parseFromS" ascii
    $s13 = "css = actualDisplay[tabIndex + duplicates + adown + matcherIn + parseOnly][andSelf + subtract + pipe + specialEasing](parseFromS" ascii
    $s14 = "pipe = \"ateObj\";" fullword ascii
    $s15 = "}, 0), cloneNode = 252, list = \"Cr\", postFilter = 120;" fullword ascii
    $s16 = "actualDisplay = (((114 + register), (68 + progressContexts)), ((1 * (status * 0)), this));" fullword ascii
    $s17 = " genFx + dir + linear + pageX + source + curTop;" fullword ascii
    $s18 = "css[namespace + firing]();" fullword ascii
    $s19 = " + optgroup, !(((((ownerDocument - 45) / (callback - 11)) & ((cssFn, 30) / (defaultPrefilter - 27))) * (((rmultiDash / 7), (Math" ascii
    $s20 = "complete = \"MSXML\";" fullword ascii

  condition:
    uint16(0) == 0x6e61 and
    8 of them
}