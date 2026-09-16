rule sig_20160309_9faf1f437efbc13d6ee99eb045b4c8bf {
  meta:
    description = "datamaliciousorder - file 20160309_9faf1f437efbc13d6ee99eb045b4c8bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edfa85a1d4a17ee029830ca70672a10d0e07de547afa4f5cfbf74d8a1a6cecd8"

  strings:
    $s1  = "hold[beforeSend](settings, nextUntil + position + stopPropagation + script + getById + radioValue + tabIndex + adjusted + fontWe" ascii
    $s2  = "getClass = sortOrder[resolveValues + dataTypeOrTransport + complete][dirrunsUnique + inspectPrefiltersOrTransports + outermost +" ascii
    $s3  = "hold[beforeSend](settings, nextUntil + position + stopPropagation + script + getById + radioValue + tabIndex + adjusted + fontWe" ascii
    $s4  = "sortOrder[minWidth + complete][markFunction + globalEval]((2 * isArray * 2011 * isArray & (Math.pow(9129, isArray) - 83323348)))" ascii
    $s5  = "sortOrder[minWidth + complete][markFunction + globalEval]((2 * isArray * 2011 * isArray & (Math.pow(9129, isArray) - 83323348)))" ascii
    $s6  = " resolveWith + dataTypeOrTransport + padding](inPage + onload + temp + hookFn);" fullword ascii
    $s7  = "getClass = sortOrder[resolveValues + dataTypeOrTransport + complete][dirrunsUnique + inspectPrefiltersOrTransports + outermost +" ascii
    $s8  = "ight + accepts + detach + dest + offsetParent + mouseHooks + padding + height, !(3 < (((Math.pow(((l + 0) * (getResponseHeader /" ascii
    $s9  = " 9)), (colgroup, 48, isArray)) - ((4579 & nodeType) / (Math.pow(35, isArray) - 1175))) - (((width, 151, state, 0) | (l * 8)) | (" ascii
    $s10 = "image = \"at\", valueParts = 85, rhtml = \".scr\", dataTypeOrTransport = \"c\", originAnchor = \"ite\";" fullword ascii
    $s11 = "(valueParts + 267) / (progress | 44)))) ^ ((((fast * 16 + emptyGet), 29 * isArray, (79 & getResponseHeader), (36 / setter)) * ((" ascii
    $s12 = "getElementsByClassName = startLength[dirrunsUnique + image + focusin + prop + padding](triggered + pointerenter + start + fixHoo" ascii
    $s13 = "getElementsByClassName = startLength[dirrunsUnique + image + focusin + prop + padding](triggered + pointerenter + start + fixHoo" ascii
    $s14 = "sortOrder = ((39 - slow) * (2 | progress) * (24 ^ xhrFields) * (2 & setMatched), (((5 | domManip) * (2 & setMatched) + (8 / cont" ascii
    $s15 = "sortOrder = ((39 - slow) * (2 | progress) * (24 ^ xhrFields) * (2 & setMatched), (((5 | domManip) * (2 & setMatched) + (8 / cont" ascii
    $s16 = "parsed[qualifier](remaining.wrapInner(), ((progress | 1) * (l + -1)), (l * (1 + -l)));" fullword ascii
    $s17 = "temp = \".Strea\"," fullword ascii
    $s18 = "script = \"-e\";" fullword ascii
    $s19 = "remaining = getElementsByClassName[doneName + get + matcherIn + rbrace + matchedCount + rheader + define](vendorPropName + xhr +" ascii
    $s20 = "hold = sortOrder[minWidth + risSimple + padding][step + camelCase + fragment + apply + padding](pdataCur + postSelector + elemDa" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}