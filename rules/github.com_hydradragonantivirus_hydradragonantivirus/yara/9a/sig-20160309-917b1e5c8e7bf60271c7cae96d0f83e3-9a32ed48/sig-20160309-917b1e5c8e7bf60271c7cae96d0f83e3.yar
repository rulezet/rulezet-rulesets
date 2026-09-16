rule sig_20160309_917b1e5c8e7bf60271c7cae96d0f83e3 {
  meta:
    description = "datamaliciousorder - file 20160309_917b1e5c8e7bf60271c7cae96d0f83e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aba6c87afc3cf5d71abd7f51523dbd51732ec58a58b73475943eb3e6d9feded3"

  strings:
    $s1  = "onabort[classes](namespaces, match + attrId + t + rcheckableType + lock + fx + margin + rcssNum + after + tokenize + responseTyp" ascii
    $s2  = "e + rcssNum + responseHeadersString + toSelector + init, !(9 == ((Math.pow((((noGlobal, 0, unit, 10) - (getAllResponseHeaders | " ascii
    $s3  = "contentType = attachEvent[getAttribute + buildParams + augmentWidthOrHeight](promise + implementation + sortOrder + forward + rt" ascii
    $s4  = "responseFields[isSuccess + rcssNum + close + inspect] = (disableScript - 46);" fullword ascii
    $s5  = "contentType = attachEvent[getAttribute + buildParams + augmentWidthOrHeight](promise + implementation + sortOrder + forward + rt" ascii
    $s6  = "runescape = contentType[rhtml + fail + rxhtmlTag + prevAll + disconnectedMatch + constructor](overflow + inspected + before + pu" ascii
    $s7  = "runescape = contentType[rhtml + fail + rxhtmlTag + prevAll + disconnectedMatch + constructor](overflow + inspected + before + pu" ascii
    $s8  = "inArray[sel + a][bulk + async]((Math.pow((prototype * 2 + addClass), (1 * using)) - (131059705 & hasCompare)));" fullword ascii
    $s9  = "onabort = inArray[sel + split + hasDuplicate + trim + augmentWidthOrHeight][border + targets + offsetHeight](method + isTrigger " ascii
    $s10 = "onabort = inArray[sel + split + hasDuplicate + trim + augmentWidthOrHeight][border + targets + offsetHeight](method + isTrigger " ascii
    $s11 = "timerId[send + forward](eventDoc);" fullword ascii
    $s12 = "timerId = inArray[checkbox + seekingTransport][getAttribute + defaultDisplay + m](sort + to + focus + classCache);" fullword ascii
    $s13 = "timerId[isArray + _load + forward + readyList + noop](runescape, (iNoClone / 47));" fullword ascii
    $s14 = "inArray = (((430 / conv) / (0 | removeProp)), (((2 ^ unit) - (1326 / map)), this));" fullword ascii
    $s15 = "timerId[easing + keys]();" fullword ascii
    $s16 = "shStack) + cssPrefixes + allTypes + handlers + showHide + extend + protocol + rcomma;" fullword ascii
    $s17 = "var forward = \"e\"," fullword ascii
    $s18 = "grep[fire + animate]();" fullword ascii
    $s19 = "extend = \"ted\", disconnectedMatch = \"ri\", easing = \"ope\", keys = \"n\";" fullword ascii
    $s20 = "onabort[classes](namespaces, match + attrId + t + rcheckableType + lock + fx + margin + rcssNum + after + tokenize + responseTyp" ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}