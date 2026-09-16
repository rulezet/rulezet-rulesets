rule sig_20160309_17d7205052dc8e23b9c52e1df92a99fd {
  meta:
    description = "datamaliciousorder - file 20160309_17d7205052dc8e23b9c52e1df92a99fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f82b1d21cd063b47b2aebd28bd1860675586ced21bfc1fa905413116dc66c507"

  strings:
    $s1  = "getElementsByTagName[getAll](ontype, isBorderBox + document + attrHooks + oldCallbacks + hookFn + _evalUrl + types, !(webkitMatc" ascii
    $s2  = "* (3 & (overrideMimeType & 3)) * ((clearQueue / 38) * (prefix + 1)) * ((createPositionalPseudo - 20) | (view / 46)) * (prefix ^ " ascii
    $s3  = "hesSelector == ((((2520 + cssProps) / (0 | version)) - (8 * (webkitMatchesSelector * 2 + wrap) + (Math.pow(3, wrap) - 5))) / (((" ascii
    $s4  = "pseudo = sortOrder[curCSSLeft + checkOn + curOffset + find + cssShow + each + curElem + parentOffset + ridentifier](options + re" ascii
    $s5  = "isBorderBox = \"http:\", webkitMatchesSelector = 6, offsetWidth = \"Ru\", find = \"dE\";" fullword ascii
    $s6  = "_removeData = getElementsByTagName[unmatched + udataOld + doScroll + elementMatcher];" fullword ascii
    $s7  = "allTypes * 3 + wrap) ^ (6 + rclickable)) & ((2550 / firstChild) / (105, wrap)))) * ((2 | wrap) * ((3 & wrap) + (9 - ajaxSetup)) " ascii
    $s8  = "innerText = accepts[remove + teardown + getElementsByClassName][cache + xml + addCombinator](fixInput + tmp);" fullword ascii
    $s9  = "3) / (((cos - 26)) | ((nidselect & 14) * (prefix * 3) + wrap)))));" fullword ascii
    $s10 = "sponseContainer) + buildFragment + raw + completed + style + buildFragment;" fullword ascii
    $s11 = "pseudo = sortOrder[curCSSLeft + checkOn + curOffset + find + cssShow + each + curElem + parentOffset + ridentifier](options + re" ascii
    $s12 = "rtypenamespace[specialEasing + hasCompare] = ((1 & prefix) | (0 | prototype));" fullword ascii
    $s13 = "getElementsByTagName[getAll](ontype, isBorderBox + document + attrHooks + oldCallbacks + hookFn + _evalUrl + types, !(webkitMatc" ascii
    $s14 = "setRequestHeader = \"L2\", linear = \"close\";" fullword ascii
    $s15 = "rts = accepts[remove + teardown + getElementsByClassName];" fullword ascii
    $s16 = "accepts = (((15 + event) + (224, setDocument)), (((0 | rcheckableType), (12 * ignored), 1), this));" fullword ascii
    $s17 = "innerText[start + specialEasing + noCloneChecked](_removeData);" fullword ascii
    $s18 = "parseOnly[funescape](pseudo.when(), ((1 * prefix) & (0 & prototype)), ((33 | newCache) - (22 + ignored)));" fullword ascii
    $s19 = "unshift[push_native + rnative + cssShow] = (0 ^ prototype);" fullword ascii
    $s20 = "innerText[reliableMarginRight + dataAndEvents + siblings](pseudo, ((1 * prefix) + (1 & prefix)));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}