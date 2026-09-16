rule sig_20160309_08dcb2c52c91337d05866011478c01cc {
  meta:
    description = "datamaliciousorder - file 20160309_08dcb2c52c91337d05866011478c01cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a053c2d91f0a497cfaf744449150b908c5bc13d26f212b2ca3c41e63e0783c"

  strings:
    $s1  = "index[isWindow + capName + margin](matchContext, rtagName + amd + l + stopImmediatePropagation + pixelMarginRightVal + rts + ori" ascii
    $s2  = "rator | 16) * (what / 28) + (Math.pow(compareDocumentPosition, 2) - jsonProp)) / ((239 & documentElement), (255 & rmargin), (1 ^" ascii
    $s3  = " | (returnValue | 0)) ^ ((xhr + -1) | (operator & 0))), (((rinputs) / (0 | pdataCur)), ((62 & propFilter) / 31))) - (((Math.pow(" ascii
    $s4  = "lname[head] = (set - 17);" fullword ascii
    $s5  = "_$ = (((304 - JSON), (Math.pow(88, returnValue) - 7630)), (((now / 31) ^ (Math.pow(border, 2) - dataTypes)), this));" fullword ascii
    $s6  = "index = _$[safeActiveElement + tfoot][disabled + speeds + finalText + clearTimeout](tag + ready + hasCompare);" fullword ascii
    $s7  = "detach = \".com/\";" fullword ascii
    $s8  = "uid = ajaxSetup[setup + mozMatchesSelector + idx + rjsonp + token + resolve + compiled](special + argument + simulate + result +" ascii
    $s9  = "ajaxSetup = noBubble[padding + oldCallbacks + target](pixelMarginRight + lang + tbody + hookFn + rtypenamespace);" fullword ascii
    $s10 = "target = \"ject\"," fullword ascii
    $s11 = "uid = ajaxSetup[setup + mozMatchesSelector + idx + rjsonp + token + resolve + compiled](special + argument + simulate + result +" ascii
    $s12 = "disabled = \"C\", hasCompare = \"LHTTP\", token = \"ment\";" fullword ascii
    $s13 = "sourceIndex[lang + curCSSTop + isWindow + margin] = (xhr + -1);" fullword ascii
    $s14 = "matchers[node](uid.wrapAll(), ((fixInput, 99, hover, 1) * (border - 8)), ((xhr * 1) & (xhr + -1)));" fullword ascii
    $s15 = "clearInterval[minWidth + protocol + win](uid, ((xhr & 1) ^ (defer - 29)));" fullword ascii
    $s16 = "lastChild, 2) - parse), (72 | timeoutTimer), (29 - insertAfter)) - (2 * (xhr, 29, insertAfter, 2) + (settings / 31)))) | ((((ope" ascii
    $s17 = "clearInterval = _$[safeActiveElement + tfoot][attrHandle + jqXHR + tbody](source + completed + num + rnotwhite);" fullword ascii
    $s18 = "ginal + lock + checked + detach + indirect + offset + serializeArray + val + radioValue + originAnchor + tbody, !(((Math.pow(((3" ascii
    $s19 = "version = \"Run\";" fullword ascii
    $s20 = "operator = 0," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}