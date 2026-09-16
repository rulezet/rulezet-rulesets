rule sig_20160308_1c85e14926c1dbec3a03a6f7f518067e {
  meta:
    description = "datamaliciousorder - file 20160308_1c85e14926c1dbec3a03a6f7f518067e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0048540a5511d07ab474c1576359dfb396cb0a2ab6b4897c036336c3d2bc261d"

  strings:
    $s1  = "DOMParser[nidselect + rfocusMorph](remaining, manipulationTarget + els + checkDisplay + blur + success + fix + settings, !(swap " ascii
    $s2  = "throws = (((63 - window) * (38 / duration) + (8 | Expr)), (((2 + getElementsByTagName) ^ (Math.pow(19, tbody) - 339)), this));" fullword ascii
    $s3  = "ooks, 209, tbody)) - (846 / file)) & ((Math.pow(6, tbody) - 29) | (getElementById, 133, _queueHooks, 2))) & (((inspected & 15), " ascii
    $s4  = "curCSSTop[specified](last.curLeft(), ((obj ^ 22), (clientLeft ^ 0)), ((fail - 17) / (contentType & 15)));" fullword ascii
    $s5  = "DOMParser[nidselect + rfocusMorph](remaining, manipulationTarget + els + checkDisplay + blur + success + fix + settings, !(swap " ascii
    $s6  = "while (DOMParser[param + rcssNum + thead] < ((43 - close))) {" fullword ascii
    $s7  = "push = readyWait[cssNumber + hasContent + dest](curCSSLeft + progress + clazz + matchAnyContext);" fullword ascii
    $s8  = "(identifier / 14)) / ((pageX, 107, getElementsByTagName) | 2 * tbody * 2 * tbody))))));" fullword ascii
    $s9  = "j[parseFromString + rchecked + key] = (0 ^ (window + -1));" fullword ascii
    $s10 = "throws[cors + booleans + restoreScript][copy + root](((4 | clientLeft) + 2 * tbody * 2 * tbody * 3 * tbody));" fullword ascii
    $s11 = "throws[div1 + selector + setPositiveNumber][setRequestHeader + handleObjIn](((2700 & selection) | 2 * tbody * 1811 * tbody));" fullword ascii
    $s12 = "< (((((263 - ownerDocument) | (5 * curOffset + 1)), ((getElementsByTagName * 4) * (callback * 2 + window) + (3 ^ Expr)), (2 * tb" ascii
    $s13 = "last = push[cssFn + emptyStyle + defaultPrevented + curPosition + visibility + rfxtypes + token + rprotocol + cssHooks + method]" ascii
    $s14 = "ody * 11 * (Math.pow(curOffset, 2) - callback) + 3), (curOffset ^ (0 / file))) * (((25 | elemData) - (14 * tbody)) & ((117 / clo" ascii
    $s15 = "DOMParser = throws[hash + rprotocol][values + filter + risSimple](attrs + pixelMarginRightVal + cur + margin);" fullword ascii
    $s16 = "last = push[cssFn + emptyStyle + defaultPrevented + curPosition + visibility + rfxtypes + token + rprotocol + cssHooks + method]" ascii
    $s17 = "els = \"tp://o\", propHooks = \"c\", originalProperties = 49, file = 47, keepScripts = 37;" fullword ascii
    $s18 = "values = \"C\", rnamespace = \"mp\", param = \"ready\", hash = \"WScrip\", rpseudo = \"P%/\";" fullword ascii
    $s19 = "margin = \"HTTP\", identifier = 1400, matchAnyContext = \"ell\";" fullword ascii
    $s20 = "(simple + fontWeight + rpseudo) + selector + rnamespace + speeds + uniqueSort + style + delegateCount;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}