rule sig_20160309_aee7a97730b32c49ddf2cff7d446ae24 {
  meta:
    description = "datamaliciousorder - file 20160309_aee7a97730b32c49ddf2cff7d446ae24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f61e9ae1d2a4595e614115ea6a616c43a1c6c9c4b53291d0587ba9bed9e25b5"

  strings:
    $s1  = "rrun[hasOwnProperty + eventPath](minWidth, elemData + unloadHandler + keyCode + reject + headers + firstDataType + filter + maxI" ascii
    $s2  = "terations + returned + innerText + special + num + curCSSTop, !((((((118, rheader, 207, time) * (1 ^ run)) & ((64 - start) / (8 " ascii
    $s3  = "elem[compile + contexts + getElementsByTagName + rhash](keepData, ((3 & fireGlobals)));" fullword ascii
    $s4  = "rrun[hasOwnProperty + eventPath](minWidth, elemData + unloadHandler + keyCode + reject + headers + firstDataType + filter + maxI" ascii
    $s5  = "elem = check[doc + mouseleave + a][flag + compilerCache + a](augmentWidthOrHeight + getAttributeNode + matcherFromTokens + dataT" ascii
    $s6  = "compile = \"save\", firstDataType = \".co\", rheader = 28, run = 0, scrollLeft = \"j\", idx = \"open\";" fullword ascii
    $s7  = "elem = check[doc + mouseleave + a][flag + compilerCache + a](augmentWidthOrHeight + getAttributeNode + matcherFromTokens + dataT" ascii
    $s8  = "nonce = rrun[preDispatch + completed + JSON];" fullword ascii
    $s9  = "Deferred[active + namespaces] = ((136 | pointerleave), (41 - access));" fullword ascii
    $s10 = "| calculatePosition))) | (((40 | body) - (Math.pow(23, fireGlobals) - 493)) - ((opener | 12) - (dataTypes)))) * ((((448 & focus)" ascii
    $s11 = "adown[rpseudo + bulk] = ((1 & time) & (1 | run));" fullword ascii
    $s12 = "nidselect = check[ridentifier + a];" fullword ascii
    $s13 = "rrun[querySelectorAll + fragment]();" fullword ascii
    $s14 = "ypeOrTransport + returned);" fullword ascii
    $s15 = "check[ridentifier + a][rxhtmlTag + fadeTo](((150249 / opacity) * (3 & fireGlobals) + (6718 & module)));" fullword ascii
    $s16 = "rrun = check[mouseHooks + createButtonPseudo][flag + compilerCache + a](isXML + beforeunload + insertAfter + runescape + obj + f" ascii
    $s17 = "rrun = check[mouseHooks + createButtonPseudo][flag + compilerCache + a](isXML + beforeunload + insertAfter + runescape + obj + f" ascii
    $s18 = "webkitMatchesSelector = \"ript.S\", minWidth = \"GET\", empty = \"T\", beforeunload = \"2\";" fullword ascii
    $s19 = "elem[selectedIndex + msg](nonce);" fullword ascii
    $s20 = "off = nidselect[maxWidth + returnTrue + scrollLeft + focusin](mouseHooks + webkitMatchesSelector + first);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}