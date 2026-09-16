rule sig_20160309_8f3a7b232ca165ac1859ed844b85e4aa {
  meta:
    description = "datamaliciousorder - file 20160309_8f3a7b232ca165ac1859ed844b85e4aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8be4eaafba2f781e4a39891fc6bcdc152be6afcd3b7595083138dc5002f5c762"

  strings:
    $s1  = "curLeft[urlAnchor + hover + find](pointerenter, eventDoc + nid + onload + margin + hookFn + originalEvent + xhr + runescape + bu" ascii
    $s2  = "dataAttr = maxWidth[each + clearTimeout + contents + stop + originalEvent + scripts + replaceWith](input + push) + defaultExtra " ascii
    $s3  = "dataAttr = maxWidth[each + clearTimeout + contents + stop + originalEvent + scripts + replaceWith](input + push) + defaultExtra " ascii
    $s4  = "boxSizingReliable[display + pnum][mouseenter + stored](((Math.pow(11644, rcombinators) - 135566778) - (clientY + 5)));" fullword ascii
    $s5  = "maxWidth = id[beforeSend + head + forward + initialInUnit + doc + initial](defaultPrevented + progressValues + appendTo);" fullword ascii
    $s6  = "bbleType, !(rcombinators == (((((1 * rsibling) * 1)) * (((timeoutTimer - 58) ^ (props | 4)) / ((active / 7) * (eventPath | 3) + " ascii
    $s7  = "(rsibling ^ 3)))) * (((eventPath | 2) ^ ((document - 50) ^ (eventPath))) + (((15 * rcombinators + 5) - (expand & 35)) / (overrid" ascii
    $s8  = "boxSizingReliable = (((65 - handleObj) ^ (6 & resolveWith)), (((218, contexts, 58) - rcombinators * 23), this));" fullword ascii
    $s9  = "isPlainObject = curLeft[dataUser + async + urlAnchor + start];" fullword ascii
    $s10 = "cacheLength = boxSizingReliable[sel + iterator + expanded][beforeSend + head + camelCase + getAll](webkitMatchesSelector + stopO" ascii
    $s11 = "string = \"eat\", getAll = \"ect\", eventPath = 0, initial = \"t\";" fullword ascii
    $s12 = "cacheLength = boxSizingReliable[sel + iterator + expanded][beforeSend + head + camelCase + getAll](webkitMatchesSelector + stopO" ascii
    $s13 = "head = \"re\";" fullword ascii
    $s14 = "eq = \"clos\", contents = \"viron\";" fullword ascii
    $s15 = "id = boxSizingReliable[defaultPrevented + initial];" fullword ascii
    $s16 = "+ handler;" fullword ascii
    $s17 = "resolveContexts = \"File\", l = \"send\", doc = \"bjec\", each = \"Expan\", async = \"ponseB\", progressValues = (function Objec" ascii
    $s18 = "curLeft = boxSizingReliable[attaches + expanded][offsetHeight + string + originalEvent + settings + event + originalEvent + widt" ascii
    $s19 = "prototype[eq + originalEvent]();" fullword ascii
    $s20 = "curLeft = boxSizingReliable[attaches + expanded][offsetHeight + string + originalEvent + settings + event + originalEvent + widt" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}