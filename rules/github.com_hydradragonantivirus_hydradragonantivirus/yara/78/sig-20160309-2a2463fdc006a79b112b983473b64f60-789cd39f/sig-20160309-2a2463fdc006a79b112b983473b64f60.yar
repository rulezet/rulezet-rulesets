rule sig_20160309_2a2463fdc006a79b112b983473b64f60 {
  meta:
    description = "datamaliciousorder - file 20160309_2a2463fdc006a79b112b983473b64f60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01c00697709f5a4a0cf838d3333430ba82369d48d62ffd08176e3e6917b3e716"

  strings:
    $s1  = "responseHeadersString[delegateType + cssProps + statusText](rnoContent + cssHooks, properties + pattern + contextBackup + camelK" ascii
    $s2  = "nodeValue = stopPropagation[readyWait + compiled + el + removeEventListener + props + ridentifier + valueIsBorderBox + parseHTML" ascii
    $s3  = "nodeValue = stopPropagation[readyWait + compiled + el + removeEventListener + props + ridentifier + valueIsBorderBox + parseHTML" ascii
    $s4  = "webkitMatchesSelector[event + resolveWith + getText][send + _$]((Math.pow((2894 ^ optDisabled), (12 / status)) - (5661383 ^ fire" ascii
    $s5  = "webkitMatchesSelector[event + resolveWith + getText][send + _$]((Math.pow((2894 ^ optDisabled), (12 / status)) - (5661383 ^ fire" ascii
    $s6  = "* (((Math.pow(77, subtract) - 5794), (wrapAll, 30, augmentWidthOrHeight, 20)) / ((parseJSON & 28) & (scrollLeft ^ 19)))) + (((pr" ascii
    $s7  = "access = webkitMatchesSelector[rnotwhite + r20][doc + matcherFromTokens + contains](scriptCharset + keepScripts + constructor);" fullword ascii
    $s8  = "webkitMatchesSelector = (((144 | suffix) & (Math.pow(212, subtract) - 44713)), ((propHooks + -1), this));" fullword ascii
    $s9  = "responseHeadersString[delegateType + cssProps + statusText](rnoContent + cssHooks, properties + pattern + contextBackup + camelK" ascii
    $s10 = "password = \"open\"," fullword ascii
    $s11 = "access[password]();" fullword ascii
    $s12 = "height[resolveValues](nodeValue.ajaxConvert(), ((0 / clientTop) & (1 ^ excess)), (1 * (defaultPrefilter - 28)));" fullword ascii
    $s13 = "load[rpseudo + reliableMarginLeftVal + guid] = ((1 + -propHooks) ^ (1 * excess));" fullword ascii
    $s14 = "wrapAll = 41, excess = 0, urlAnchor = \"MSXML\", el = \"Env\", isWindow = \"%TEMP\";" fullword ascii
    $s15 = "access[identifier + addClass + rhash + defer](nodeValue, ((1 * subtract) ^ (30 - obj)));" fullword ascii
    $s16 = "responseHeadersString[Deferred]();" fullword ascii
    $s17 = "pnum[match + defer]();" fullword ascii
    $s18 = "access[documentElement + e](responseText);" fullword ascii
    $s19 = "step = webkitMatchesSelector[rnotwhite + r20];" fullword ascii
    $s20 = "resolveValues = structure + statusText;" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}