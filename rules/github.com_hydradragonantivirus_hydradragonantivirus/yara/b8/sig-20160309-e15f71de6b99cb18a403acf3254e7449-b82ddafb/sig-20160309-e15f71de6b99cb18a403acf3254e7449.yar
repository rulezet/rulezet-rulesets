rule sig_20160309_e15f71de6b99cb18a403acf3254e7449 {
  meta:
    description = "datamaliciousorder - file 20160309_e15f71de6b99cb18a403acf3254e7449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b1f2550bb93703b127745c9da2b4aba94f1c73fb0e320aee727b35b9dc409a1"

  strings:
    $s1  = "contains = excess[contents + compiled + fireWith](boxSizingReliableVal + operator + getStyles + pointerenter + isArrayLike);" fullword ascii
    $s2  = "slow[noCloneChecked + l](tag + globalEventContext, getBoundingClientRect + noBubble + rnotwhite + matchAnyContext + realStringOb" ascii
    $s3  = "slow = testContext[boxSizingReliableVal + root + cssProps + getStyles][xhrSupported + parentNode + view + fireWith](fx + matcher" ascii
    $s4  = "slow = testContext[boxSizingReliableVal + root + cssProps + getStyles][xhrSupported + parentNode + view + fireWith](fx + matcher" ascii
    $s5  = "module = \"E\", rtagName = \"x.com/\", responseHeaders = \"save\", rts = \"S\";" fullword ascii
    $s6  = "ate | 48))) - (Math.pow((Math.pow((rhash ^ 0), (minWidth, 175, replaceAll)) - (4012 / animation)), ((1 * etag) * (12 - propHooks" ascii
    $s7  = "queue = \"sty\", pipe = \"Script\", isEmptyObject = 43;" fullword ascii
    $s8  = "options = \"%TEMP%\"," fullword ascii
    $s9  = "testContext = (((184 + nid) | (429 / random)), (((Math.pow(6, replaceAll) - 29) & (unit | 5)), this));" fullword ascii
    $s10 = "source[docElem](actualDisplay.has(), ((17 - animation) ^ (0 / propHooks)), (0 / (delay * 2 + toSelector)));" fullword ascii
    $s11 = "indirect = testContext[boxSizingReliableVal + pipe][addHandle + globalEval + iterator](funcName + pageYOffset + pos + setAttribu" ascii
    $s12 = "indirect = testContext[boxSizingReliableVal + pipe][addHandle + globalEval + iterator](funcName + pageYOffset + pos + setAttribu" ascii
    $s13 = "actualDisplay = contains[module + selectedIndex + charCode + content + ajaxExtend + rts + outermost + l + margin](options + ease" ascii
    $s14 = "actualDisplay = contains[module + selectedIndex + charCode + content + ajaxExtend + rts + outermost + l + margin](options + ease" ascii
    $s15 = "slow[noCloneChecked + l](tag + globalEventContext, getBoundingClientRect + noBubble + rnotwhite + matchAnyContext + realStringOb" ascii
    $s16 = "indirect[responseHeaders + globalEventContext + results + parentNode](actualDisplay, (etag * (2 & toSelector)));" fullword ascii
    $s17 = "))) - ((502 & reset) & (343 + andSelf))))) == 6));" fullword ascii
    $s18 = "FromTokens + offsetWidth + subtract + curLeft);" fullword ascii
    $s19 = "getStyles = \"t\", stopped = \"on\";" fullword ascii
    $s20 = "noCloneChecked = \"ope\", isBorderBox = 18, opts = 698, eased = \"/\", operator = \"Scrip\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}