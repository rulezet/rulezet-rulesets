rule sig_20160309_184d16ea68471823d778cb61dffd11c8 {
  meta:
    description = "datamaliciousorder - file 20160309_184d16ea68471823d778cb61dffd11c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "146f44c62b9da0470d5f66fbfdd10c61c66cede4fa9b0ed5f4f23988924ed3bd"

  strings:
    $s1  = "nid[expand + pixelPosition](rparentsprev + dataType, disabled + expanded + hasCompare + style + camelCase + rsubmittable + pnum " ascii
    $s2  = "timer = easing[fns + async][idx + lastChild + pipe + computed](hash + preMap + scriptCharset + hasScripts + map);" fullword ascii
    $s3  = ") - (((currentTarget + 33) / (prototype, 173, string)) * (3 & (setOffset * 2)) * (requestHeadersNames | (0 & setOffset)) * (2, c" ascii
    $s4  = "crossDomain = size[inArray + dirruns + getAttribute + pixelPosition + ownerDocument + what + off](name + guaranteedUnique + hand" ascii
    $s5  = "origName[bySet](crossDomain.simulate(), ((0 / delegate) / (Math.pow(15, requestHeadersNames) - 209)), ((clazz | 30) - (nativeSta" ascii
    $s6  = "origName[bySet](crossDomain.simulate(), ((0 / delegate) / (Math.pow(15, requestHeadersNames) - 209)), ((clazz | 30) - (nativeSta" ascii
    $s7  = "leObj) + setMatchers + pipe + parseOnly + getComputedStyle + attrHooks;" fullword ascii
    $s8  = "easing = (((95 ^ toggleClass) - (192 / val)), (((23 - serializeArray) ^ (Math.pow(15, requestHeadersNames) - 201)), this));" fullword ascii
    $s9  = "crossDomain = size[inArray + dirruns + getAttribute + pixelPosition + ownerDocument + what + off](name + guaranteedUnique + hand" ascii
    $s10 = "+ b + genFx + when + matchedCount, !((Math.pow(((((Math.pow(first, 2) - isNumeric) | (1 * subordinate)) | ((160 | time) / (2 * e" ascii
    $s11 = "size = rclass[scrollTop + pipe + replaceWith + getElementsByClassName + async](documentIsHTML + gotoEnd + caption + parse);" fullword ascii
    $s12 = "async = \"t\", mappedTypes = \"ite\", headers = 107, safeActiveElement = 87, expand = \"ope\", unbind = \"Run\";" fullword ascii
    $s13 = "proxy[obj + holdReady + risSimple]();" fullword ascii
    $s14 = "timer[related + getResponseHeader + noGlobal](crossDomain, ((1 + subordinate) * 2));" fullword ascii
    $s15 = "overflowX[selected + matchContext + charCode] = ((1 * setOffset) & (103, contentDocument, 132, subordinate));" fullword ascii
    $s16 = "ventHandle + 1))), ((beforeunload * 41 / (hasFocus & 43)) * ((factory, 103, cssFn, 0) | (rprotocol + 8)) + ((fxNow - 27) - (elem" ascii
    $s17 = "easing[unit + attrHooks + high][closest + completed]((factory / 17) * (parentOffset & 2) * (subordinate | 5) * (setOffset * 3) *" ascii
    $s18 = "timer[defaultDisplay + mappedTypes](exports);" fullword ascii
    $s19 = "easing[unit + attrHooks + high][closest + completed]((factory / 17) * (parentOffset & 2) * (subordinate | 5) * (setOffset * 3) *" ascii
    $s20 = "pipe = \"O\";" fullword ascii

  condition:
    uint16(0) == 0x6970 and
    8 of them
}