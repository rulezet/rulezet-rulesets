rule sig_20160308_a11aad3cb2968ae3880c968896ab74cb {
  meta:
    description = "datamaliciousorder - file 20160308_a11aad3cb2968ae3880c968896ab74cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51d69d8eff115f55a03efbfe5f8338465811d6569a8786fd44224ef8f0ce371c"

  strings:
    $x1  = "getElementById[conv2 + textContent](colgroup + keyCode, doneName + unquoted + reset + nonce + isHidden + rneedsContext + createB" ascii
    $s2  = "suffix = pointerenter[setter + rbrace + delegate + slideUp + identifier + cur + undelegate + computed](hookFn + includeWidth) + " ascii
    $s3  = "getElementById[conv2 + textContent](colgroup + keyCode, doneName + unquoted + reset + nonce + isHidden + rneedsContext + createB" ascii
    $s4  = "updateFunc + html + temp + getAllResponseHeaders;" fullword ascii
    $s5  = "value[preventDefault + keepScripts + optSelected + ready](suffix, ((getAll | 2) | (r20, 88, isSuccess, 0)));" fullword ascii
    $s6  = "value[triggered + module + relatedTarget](getElementById[end + slideToggle + getStyles + noConflict + fireWith]);" fullword ascii
    $s7  = "sortDetached = (((95256 / insertAfter) / (23 & overrideMimeType)), (((12 + showHide) & (0 | rootjQuery)), this));" fullword ascii
    $s8  = "hooks = sortDetached[file + password + ajaxSetup];" fullword ascii
    $s9  = "while (getElementById[getAllResponseHeaders + swap + offsetParent + compiled] < ((1 + getAll) * (12 / setDocument))) {" fullword ascii
    $s10 = "stModified) & (24 + augmentWidthOrHeight)) - ((241 + time) / (1178 / setFilters))) & (Math.pow(((3 * setDocument + 1) * (showHid" ascii
    $s11 = "e * 2) + (rootjQuery & 9)), (showHide * (2 | bool))) - ((878 & superMatcher) & (211 ^ elemLang)))))));" fullword ascii
    $s12 = "pointerenter = hooks[flatOptions + relatedTarget + ret + Sizzle + uniqueSort](err + caption + timeStamp + hasFocus + clientY);" fullword ascii
    $s13 = "suffix = pointerenter[setter + rbrace + delegate + slideUp + identifier + cur + undelegate + computed](hookFn + includeWidth) + " ascii
    $s14 = "uttonPseudo + n + sourceIndex + linear + defaultPrefilter, !(4 == (((((finish / 1) ^ (finish + 17)) ^ ((scriptCharset ^ 45) | (g" ascii
    $s15 = "getElementById = sortDetached[marginLeft + timeStamp][contexts + td + mozMatchesSelector + propFix + tfoot](next + matchContext " ascii
    $s16 = "getElementById = sortDetached[marginLeft + timeStamp][contexts + td + mozMatchesSelector + propFix + tfoot](next + matchContext " ascii
    $s17 = "etAttributeNode + 5))) & (((showHide | 5) | (getAll | 103)) ^ bool * (2 ^ getAll) * (91, parentsUntil, 35, bool))) / ((((81 | la" ascii
    $s18 = "password = \"Scr\";" fullword ascii
    $s19 = "temp = \".sc\";" fullword ascii
    $s20 = "    sortDetached[file + code + uniqueSort][_jQuery + add](((92, removeProp, 118, hasOwnProperty) - (Math.pow(65, bool) - 4150)))" ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}