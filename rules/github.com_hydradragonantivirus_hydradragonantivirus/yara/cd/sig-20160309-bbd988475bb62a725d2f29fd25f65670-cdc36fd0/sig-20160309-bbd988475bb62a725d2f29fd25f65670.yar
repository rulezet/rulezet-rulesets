rule sig_20160309_bbd988475bb62a725d2f29fd25f65670 {
  meta:
    description = "datamaliciousorder - file 20160309_bbd988475bb62a725d2f29fd25f65670.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e42da926490c01d608eb02cbb6553ac488cfc24b5c56d6566617eeca9003aa82"

  strings:
    $s1  = "inPage[done](rpseudo, removeAttr + accepts + rkeyEvent + register + crossDomain + undelegate + clearInterval + seekingTransport " ascii
    $s2  = "setOffset = getResponseHeader[Callbacks + boxSizingReliable + rscriptTypeMasked + radioValue + matchedCount + prev](attrHandle +" ascii
    $s3  = "* (ontype, 81, keepScripts)) & (((8212 | minWidth) | (18005 - inArray)) / (5 | detach) * (7 ^ refElements))), ((((116 - type) + " ascii
    $s4  = "scriptCharset[height + funcName + xhrSupported + removeEvent](setOffset, (dispatch - 20));" fullword ascii
    $s5  = " rkeyEvent) + createPseudo + compareDocumentPosition + button + currentTime + noGlobal;" fullword ascii
    $s6  = "rkeyEvent = \"/\", rpseudo = \"GET\", Callbacks = \"Expand\", hold = 70, resolveValues = \"Script\", dirrunsUnique = \"S\";" fullword ascii
    $s7  = " expanded)) * (Math.pow((1 ^ wrapInner), (2 | refElements)) - (Math.pow(3, wrapInner) - 4)) + (qualifier / 11) * (tabIndex ^ 2) " ascii
    $s8  = "prefilterOrFactory[target] = ((23 / namespaces) * (1 + refElements));" fullword ascii
    $s9  = "inPage[done](rpseudo, removeAttr + accepts + rkeyEvent + register + crossDomain + undelegate + clearInterval + seekingTransport " ascii
    $s10 = " | 25), (specialEasing ^ 234), (expanded * 3 + parsed)), ((1 & tabIndex) * 2)) - ((rsibling, 76, protocol), (226, always, 11, cr" ascii
    $s11 = "var attrHandle = \"%TEMP%\"," fullword ascii
    $s12 = "2 + (refElements / 39)) * ((wrapInner + 0) | ((refElements | 0) | (dataType - 14))))) == (((Math.pow((protocol * 3, (newSelector" ascii
    $s13 = "target = \"type\";" fullword ascii
    $s14 = "visible[trigger](setOffset.nid(), ((tabIndex | 0) * refElements), (1 * (refElements ^ 0)));" fullword ascii
    $s15 = "(2 * wrapInner + 1)) & ((Math.pow(src, 2) - rCRLF) ^ (74 | compile))) & ((22 + eventDoc) / (1849 / parts)) * (3 & (parsed))), ((" ascii
    $s16 = "scriptCharset = valueIsBorderBox[select + reverse + addHandle][preDispatch + escapedWhitespace + propHooks + hookFn](version + d" ascii
    $s17 = "scriptCharset = valueIsBorderBox[select + reverse + addHandle][preDispatch + escapedWhitespace + propHooks + hookFn](version + d" ascii
    $s18 = "getResponseHeader = index[preDispatch + mapped + hookFn](optDisabled + result + parse + active + newUnmatched + context);" fullword ascii
    $s19 = "valueIsBorderBox = (((0 ^ refElements) | (359 - percent)), ((7 + parsed * 2 * wrapInner), this));" fullword ascii
    $s20 = "inPage = valueIsBorderBox[settings + dirrunsUnique + postSelector + parse][byElement + getClientRects + swap + className](attrib" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}