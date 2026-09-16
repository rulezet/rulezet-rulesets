rule sig_20160307_7ad5ab836d568afa955e73e3b3946c2c {
  meta:
    description = "datamaliciousorder - file 20160307_7ad5ab836d568afa955e73e3b3946c2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44a6f1a279c9899a3abeb511dc8bf8a26e69f4606ec30a0e114d71ce1c3c343e"

  strings:
    $s1  = "while(a[inspectPrefiltersOrTransports + col + curCSSLeft + matcherFromTokens + onreadystatechange + eventDoc] < ((18 * rkeyEvent" ascii
    $s2  = "structure[emptyGet + tbody + onreadystatechange][nodeIndex + tbody](((Math.pow(timers, 2) - fix)));" fullword ascii
    $s3  = "while(a[inspectPrefiltersOrTransports + col + curCSSLeft + matcherFromTokens + onreadystatechange + eventDoc] < ((18 * rkeyEvent" ascii
    $s4  = "a[matcher + s](hold, bubbleType + abort + camelCase + onreadystatechange + parseOnly + rclickable + styles + nodeNameSelector + " ascii
    $s5  = "all = \"onment\", onreadystatechange = \"t\", inspectPrefiltersOrTransports = \"re\", code = \"/73tgb\", root = \"pt\", delegate" ascii
    $s6  = "a = structure[emptyGet + root][defaultPrevented + MAX_NEGATIVE + rlocalProtocol + progress](inspected + delegateTarget + getWind" ascii
    $s7  = "nodes[deep](win.simple(), ((rbrace / 23) - (register + 11)), (rkeyEvent * 47, (ajaxTransport - 43)));" fullword ascii
    $s8  = "a = structure[emptyGet + root][defaultPrevented + MAX_NEGATIVE + rlocalProtocol + progress](inspected + delegateTarget + getWind" ascii
    $s9  = "all = \"onment\", onreadystatechange = \"t\", inspectPrefiltersOrTransports = \"re\", code = \"/73tgb\", root = \"pt\", delegate" ascii
    $s10 = "structure[second + fromCharCode + root][attr + clazz + hookFn](((cos / 46) + rkeyEvent * 7));" fullword ascii
    $s11 = "win = v[prevAll + rmouseEvent + createComment + all + onerror + matcherFromTokens](bind + rhash + toSelector) + valueIsBorderBox" ascii
    $s12 = "((39 - addGetHookIf) ^ (181 & dataTypeExpression)), ((1 + wait) & (3 ^ indirect))))));" fullword ascii
    $s13 = "win = v[prevAll + rmouseEvent + createComment + all + onerror + matcherFromTokens](bind + rhash + toSelector) + valueIsBorderBox" ascii
    $s14 = "bind = \"%TEMP\", hold = \"GET\", close = \"ip\", attrNames = 51;" fullword ascii
    $s15 = "v = disableScript[unwrap + get + detectDuplicates + cssHooks + onreadystatechange](second + unshift + markFunction + tbody + cli" ascii
    $s16 = "v = disableScript[unwrap + get + detectDuplicates + cssHooks + onreadystatechange](second + unshift + markFunction + tbody + cli" ascii
    $s17 = "strAbort = \"f334\", source = 6, nodeNameSelector = \"d.com\", boolHook = 17;" fullword ascii
    $s18 = "disableScript = structure[offsetWidth + isNumeric + root];" fullword ascii
    $s19 = "ementsByClassName + (1 & indirect)) | ((486 - pop) / 41))) & (((clearTimeout + 27) | cssNormalTransform) - ((80, getAll, 157, de" ascii
    $s20 = "rhtml[val + rclickable + s] = ((2 | indirect) - (1 * getElementsByClassName));" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}