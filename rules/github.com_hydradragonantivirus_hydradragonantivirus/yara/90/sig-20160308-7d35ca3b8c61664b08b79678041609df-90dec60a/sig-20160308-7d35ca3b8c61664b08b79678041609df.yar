rule sig_20160308_7d35ca3b8c61664b08b79678041609df {
  meta:
    description = "datamaliciousorder - file 20160308_7d35ca3b8c61664b08b79678041609df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "822abcf401c8203a795c4220ab08a4e732bc14314d514ca6a820a13aeb3345fd"

  strings:
    $s1  = "nType[delegateType](until + pixelPosition, extend + calculatePosition + bind + callbackInverse + preferredDoc + prepend + domMan" ascii
    $s2  = "setTimeout[reject + handleObj + compiled + cssExpand] = ((Math.pow(14, getElementById) - 177), (evt | 240), (options * 0));" fullword ascii
    $s3  = "etElementById))) & (((10 & test) ^ (38 / getElementById)) - ((41 & unmatched) - (1 ^ status))))) - (((Math.pow(119, getElementBy" ascii
    $s4  = "rrun = \"X\", temp = \"lo\", beforeunload = \"WScrip\", operator = \"To\";" fullword ascii
    $s5  = "getElementsByName[getWidthOrHeight + set + hover + inPage][children]((2 * rhtml - (4455 + rcheckableType)));" fullword ascii
    $s6  = "tipleContexts))), (((34 / argument) * 19 * (options * 2) * (options * 2), (td * (1 * getElementById) + (25 | qsaError)), ((3 & g" ascii
    $s7  = " (2 & Callbacks)) - 2 * thead * 5 * getElementById * 73) / ((run - 28) * Callbacks + (2, unit, 9))) + (getElementById + (1 * mul" ascii
    $s8  = "nType = getElementsByName[beforeunload + handleObj][iNoClone + bulk + deepDataAndEvents + nodeValue](defineProperty + actualDisp" ascii
    $s9  = "nonce[cssProps + temp + button]();" fullword ascii
    $s10 = "mimeType = hasFocus[readyState + state + rmsPrefix + offsetWidth](timeoutTimer + filter + compiled + inPage + isArrayLike + end " ascii
    $s11 = "nonce[easing + compiled + initial](nType[prevUntil + guaranteedUnique + seekingTransport]);" fullword ascii
    $s12 = "mimeType = hasFocus[readyState + state + rmsPrefix + offsetWidth](timeoutTimer + filter + compiled + inPage + isArrayLike + end " ascii
    $s13 = "extend = \"http:\";" fullword ascii
    $s14 = "getElementsByName = (((4944 / documentIsHTML) + (55 * Callbacks)), (((67 - ajax)), this));" fullword ascii
    $s15 = "valHooks[head] = ((1 & options) * (1 * options));" fullword ascii
    $s16 = "nonce[attributes + overwritten + operator + clientX](isSuccess, (multipleContexts | 2));" fullword ascii
    $s17 = "nType = getElementsByName[beforeunload + handleObj][iNoClone + bulk + deepDataAndEvents + nodeValue](defineProperty + actualDisp" ascii
    $s18 = "    getElementsByName[getWidthOrHeight + set + hover + inPage][ret + dequeue](((179 - replaceWith) & (3348 / unwrap)));" fullword ascii
    $s19 = "Id) - 13932), (optSelected + 268)) / ((startTime & 7) ^ (flatOptions, 179, index))) * ((14 - handleObjIn) + ((0 | multipleContex" ascii
    $s20 = "nonce = getElementsByName[getWidthOrHeight + checkClone + oldCache + inPage][newSelector + promise + initial + getElementsByClas" ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}