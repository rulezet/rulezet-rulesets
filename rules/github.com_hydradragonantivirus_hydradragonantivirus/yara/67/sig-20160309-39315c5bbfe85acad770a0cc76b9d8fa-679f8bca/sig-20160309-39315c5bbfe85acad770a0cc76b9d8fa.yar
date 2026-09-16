rule sig_20160309_39315c5bbfe85acad770a0cc76b9d8fa {
  meta:
    description = "datamaliciousorder - file 20160309_39315c5bbfe85acad770a0cc76b9d8fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2913d79bc4dc6edbe99262e81b6756b859d6cbfdb5e9c405b0cad1823777b688"

  strings:
    $s1  = "simple[XMLHttpRequest](optSelected, stopOnFalse + toggle + async + random + rnamespace + setFilters, !((((1 * extend) | ((3 & se" ascii
    $s2  = "+ (72, extend, 82, forward)) / (Math.pow((31 - globalEventContext), (1 * setter)) - (287 - rnative))) + ((((Math.pow(4, setter) " ascii
    $s3  = "reject[rmsPrefix + on] = ((restoreScript & 255), (converters & 126), (matcher - 156), (extend / 30));" fullword ascii
    $s4  = "parentsUntil = rheader[to + fxNow + configurable + e + view + getAll + preferredDoc](rheaders + prev) + replaceAll + onload + fi" ascii
    $s5  = "rheader = conv2[boxSizingReliable + insertAfter + els](serializeArray + username + rsubmittable + wait);" fullword ascii
    $s6  = "resolveWith[tuple](parentsUntil.sel(), (1 * extend), ((1 + extend) & (0 / getAttributeNode)));" fullword ascii
    $s7  = "parentsUntil = rheader[to + fxNow + configurable + e + view + getAll + preferredDoc](rheaders + prev) + replaceAll + onload + fi" ascii
    $s8  = "restoreScript = 191, forward = 11, unshift = \"close\", splice = \"se\";" fullword ascii
    $s9  = "tter)) * ((Math.pow(162, setter) - 25996), (Math.pow(one, 2) - ownerDocument), (384 / func), (27 - nodeType))) * (((22 ^ speed) " ascii
    $s10 = "unbind = (((Math.pow(17, setter) - 267) & (Math.pow(nonce, 2) - rsubmitterTypes)), (((34 - cacheURL) ^ (0 | extend)), this));" fullword ascii
    $s11 = "extend / 38)) ^ ((send + -1) | (resolveValues - 28))))) == maxWidth));" fullword ascii
    $s12 = "unbind[serializeArray + all + th + nextSibling][createComment + cssText](((slideToggle * 4 + copy) | (4869 + option)));" fullword ascii
    $s13 = "conv2 = unbind[whitespace + setPositiveNumber + mimeType];" fullword ascii
    $s14 = "unmatched = simple[handleObj + rcomma + stopPropagation];" fullword ascii
    $s15 = "simple[XMLHttpRequest](optSelected, stopOnFalse + toggle + async + random + rnamespace + setFilters, !((((1 * extend) | ((3 & se" ascii
    $s16 = "simple = unbind[pattern + scrollTop][includeWidth + s + mimeType](gotoEnd + padding + firingIndex);" fullword ascii
    $s17 = "converters = 127, rheaders = \"%T\", toggle = \"/hipno\", nonce = 18, rsubmitterTypes = 293;" fullword ascii
    $s18 = "propHooks[fireWith + unit + value](unmatched);" fullword ascii
    $s19 = "propHooks[margin + iNoClone](parentsUntil, ((setter & 3)));" fullword ascii
    $s20 = "ler + expand + deep);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}