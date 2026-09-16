rule sig_20160309_333482372205d2915ed3a57b9aaeaa63 {
  meta:
    description = "datamaliciousorder - file 20160309_333482372205d2915ed3a57b9aaeaa63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4c1d7027613d370a6051e3c7a5d7561ca173d5338d8113e0acc3aff4d94f934"

  strings:
    $s1  = "rscriptTypeMasked[related + tokenCache](uniqueSort + createFxNow, scrollTop + parseFromString + p + percent + url + rts + attach" ascii
    $s2  = "ready[boolHook + timer + type][forward](((30959 & whitespace) - 5 * hookFn));" fullword ascii
    $s3  = " / (Math.pow((35 - _load), 2) - (evt / 21))) * ((contentDocument, 76, duration) & ((1 * duration) & (1 + _load)))))));" fullword ascii
    $s4  = "& (duration & 1)) ^ (duration * 3))) - ((Math.pow(context, 2) - pointerleave) + (10 ^ _load))) | ((((363 - display) / 3 * token)" ascii
    $s5  = "ready = ((2 * param + (45 + fnOut)), (((Math.pow(22, param) - 453) - fns), this));" fullword ascii
    $s6  = "run[getAttributeNode + jsonp + mouseHooks](tick, ((0 ^ param) | (0 ^ _load)));" fullword ascii
    $s7  = "rscriptTypeMasked = ready[before + classNames][selectedIndex + scale + slideUp + type](backgroundClip + isArrayLike + attrHooks " ascii
    $s8  = "cloneNode = teardown[argument + dirrunsUnique + attrNames + border](second + guid + key);" fullword ascii
    $s9  = "teardown = ready[boolHook + tokens + rchecked + parseFromString + type];" fullword ascii
    $s10 = "Event + tweeners + overflowX + stopImmediatePropagation + computed + empty + tokenCache, !(6 < ((Math.pow((Math.pow(((Math.pow(t" ascii
    $s11 = "rscriptTypeMasked[related + tokenCache](uniqueSort + createFxNow, scrollTop + parseFromString + p + percent + url + rts + attach" ascii
    $s12 = "+ triggered + getBoundingClientRect);" fullword ascii
    $s13 = "oken, 2) - guaranteedUnique) & (3 ^ checkbox)), ((651 / valueParts) - (1 ^ curCSS))) - ((2 ^ duration) + (186 / special))), ((1 " ascii
    $s14 = "source = \"TEMP%/\";" fullword ascii
    $s15 = "run = ready[needsContext + type][booleans + nodeValue + hold](selector + mozMatchesSelector + j + activeElement + ontype);" fullword ascii
    $s16 = "tick = cloneNode[response + append + binary + div + accepts + showHide](arg + source) + contextBackup + ontype + ajaxSetup + rta" ascii
    $s17 = "tick = cloneNode[response + append + binary + div + accepts + showHide](arg + source) + contextBackup + ontype + ajaxSetup + rta" ascii
    $s18 = "subordinate = rscriptTypeMasked[runescape + done + cssPrefixes];" fullword ascii
    $s19 = "rscriptTypeMasked = ready[before + classNames][selectedIndex + scale + slideUp + type](backgroundClip + isArrayLike + attrHooks " ascii
    $s20 = "forward = \"Sleep\";" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}