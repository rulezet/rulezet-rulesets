rule sig_20160311_c9361bc6d2c4738f86e9fb94b86a057f {
  meta:
    description = "datamaliciousorder - file 20160311_c9361bc6d2c4738f86e9fb94b86a057f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a97694e5b35b316c326dcf8040c958002ce2d651c064ea9c75469fefb39096fe"

  strings:
    $s1  = "jqXHR[\"o\" + tmp + \"n\"](last + \"T\".visible(), opt + \"p://\" + selectors + \"ofi\" + defaultView + \"om/\".visible() + conv" ascii
    $s2  = "isSimulated[success + \"n\"](finalDataType.visible(((Math.pow(47, hasFocus) - 2139) + (Math.pow(p, 2) - ready))), ((Math.pow(20," ascii
    $s3  = "finalDataType = pushStack[\"Exp\" + fire + \"iron\".visible() + srcElements + \"String\" + root](\"%TEMP\" + responseType) + \"m" ascii
    $s4  = "mappedTypes)) / ((396 / content) & (Math.pow(7, hasFocus) - 38))) + ((doc) / (19 & ifModified))) + ((((528 | contains) / 24) - (" ascii
    $s5  = "inspectPrefiltersOrTransports[\"t\" + completeDeferred + \"e\".visible()] = ((getBoundingClientRect) | (241, copy, 47, getBoundi" ascii
    $s6  = "inspectPrefiltersOrTransports[\"t\" + completeDeferred + \"e\".visible()] = ((getBoundingClientRect) | (241, copy, 47, getBoundi" ascii
    $s7  = "finalDataType = pushStack[\"Exp\" + fire + \"iron\".visible() + srcElements + \"String\" + root](\"%TEMP\" + responseType) + \"m" ascii
    $s8  = "isSimulated[success + \"n\"](finalDataType.visible(((Math.pow(47, hasFocus) - 2139) + (Math.pow(p, 2) - ready))), ((Math.pow(20," ascii
    $s9  = "isPropagationStopped = ((11 | (Math.pow(markFunction, 2) - innerHTML)), ((44 - prefix) + (178, replaceChild, 93, matchExpr)), ev" ascii
    $s10 = "isPropagationStopped = ((11 | (Math.pow(markFunction, 2) - innerHTML)), ((44 - prefix) + (178, replaceChild, 93, matchExpr)), ev" ascii
    $s11 = "webkitMatchesSelector * 2 * hasFocus * 7, (Math.pow(sortDetached, 2) - simple))) * (((765 / htmlPrefilter) - (18 * hasFocus + 14" ascii
    $s12 = "((((3 & (doc | 2)) - ((augmentWidthOrHeight | 7) - name * 7)) | (Math.pow(name, 2) - conditionFn)) * ((((21 | mimeType) & (33 & " ascii
    $s13 = "jqXHR[root + \"e\" + identifier]();" fullword ascii
    $s14 = "jqXHR[\"o\" + tmp + \"n\"](last + \"T\".visible(), opt + \"p://\" + selectors + \"ofi\" + defaultView + \"om/\".visible() + conv" ascii
    $s15 = "content = 36," fullword ascii
    $s16 = "ible() + _evalUrl + \"sc\" + related;" fullword ascii
    $s17 = "b[rchecked + \"oFile\"](finalDataType, (33, define, 2));" fullword ascii
    $s18 = "visible() + DOMParser);" fullword ascii
    $s19 = "}, 227), hasFocus = 2, sortDetached = 18, ready = 177;" fullword ascii
    $s20 = "identifier = \"nd\";" fullword ascii

  condition:
    uint16(0) == 0x6469 and
    8 of them
}