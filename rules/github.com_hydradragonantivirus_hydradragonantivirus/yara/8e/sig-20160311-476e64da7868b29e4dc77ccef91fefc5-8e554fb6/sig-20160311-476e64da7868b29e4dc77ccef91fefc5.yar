rule sig_20160311_476e64da7868b29e4dc77ccef91fefc5 {
  meta:
    description = "datamaliciousorder - file 20160311_476e64da7868b29e4dc77ccef91fefc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "026a9a19cdcf4704d2f170c106b1441b8da73789d64aed46597285a397501c47"

  strings:
    $x1  = "_load[\"op\" + runescape](\"G\" + offset + \"T\".scale(), fireWith + \"/no\" + callbackInverse + \"s.cz\" + offsetWidth + \"4h45" ascii
    $s2  = "* (Math.pow((restoreScript), (2 + xhrFields)) - (418 / input)) / ((Math.pow((5 - relative), 2) - (splice | 8)) & ((xhrFields | 1" ascii
    $s3  = " _removeData))), (((165, factory, 30) / (sortDetached - 23)) * (Math.pow((Math.pow(setDocument, 2) - target), (2 | _removeData))" ascii
    $s4  = "!((Math.pow((((getAttributeNode - 1) * (splice * 2 + relative) - ((Math.pow(6, _removeData) - 28) | (getBoundingClientRect * 4 +" ascii
    $s5  = "2 * splice * 13 / (Math.pow(matcherFromTokens, 2) - inArray)) * ((135, currentValue, 1) * _removeData) + ((238, opener, 1) + (_q" ascii
    $s6  = "unloadHandler[val + \"eToFil\".scale() + abort](actualDisplay, ((setDocument * 5 + splice) - (76 - target)));" fullword ascii
    $s7  = " - (64 | nType)) + (1 * _removeData)), (((2 * restoreScript + 1) * splice + (35 - Callbacks)) - (Math.pow((Math.pow(14, _removeD" ascii
    $s8  = "((((current / 48) - (notifyWith + 148)) / ((includeWidth / 46) / (getClientRects & 63))) * (locked - (90 / addGetHookIf))) - (((" ascii
    $s9  = "ueueHooks - 45))) * (((resolveWith / 36), (locked - 3)) & _removeData) + (((1 + _removeData) * (115, dataTypeOrTransport, 14) + " ascii
    $s10 = "ata) - 179), (converters / 27)) - (removeAttribute + 181)))), (((Math.pow(second, 2) - initialInUnit) - (135, _queueHooks, 50)) " ascii
    $s11 = "origFn[rclickable + \"pe\"] = ((stopped * 2 + _removeData) / (10 + restoreScript));" fullword ascii
    $s12 = "target = 40, offsetHeight = \"ntStr\", _queueHooks = 45, toggleClass = 4083, runescape = \"en\", second = 31;" fullword ascii
    $s13 = "checkDisplay[replaceAll + \"n\"](actualDisplay.scale(((Math.pow(15, _removeData) - 196) + (handler | 52))), ((namespace - 42) + " ascii
    $s14 = "checkDisplay[replaceAll + \"n\"](actualDisplay.scale(((Math.pow(15, _removeData) - 196) + (handler | 52))), ((namespace - 42) + " ascii
    $s15 = "   vendorPropName = \"%TEMP%\"," fullword ascii
    $s16 = "offset = \"E\", restoreScript = 4, removeAttribute = 85, dataType = \"ll\", current = 26256, sortDetached = 33;" fullword ascii
    $s17 = "function getElementById() {" fullword ascii
    $s18 = "copy = \"Cre\", getBoundingClientRect = 12;" fullword ascii
    $s19 = "unloadHandler = flatOptions[get + \"ipt\".scale()][copy + \"ate\" + dispatch](\"ADODB.\" + props);" fullword ascii
    $s20 = "props = \"Stream\", getClientRects = 50;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}