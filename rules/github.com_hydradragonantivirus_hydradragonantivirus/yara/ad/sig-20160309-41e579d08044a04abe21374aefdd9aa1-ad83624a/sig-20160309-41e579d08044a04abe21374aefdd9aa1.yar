rule sig_20160309_41e579d08044a04abe21374aefdd9aa1 {
  meta:
    description = "datamaliciousorder - file 20160309_41e579d08044a04abe21374aefdd9aa1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e019d2e57dbab74c4b987da7c29a4df8a0d060750bb4961c47a7bee72ad72c9"

  strings:
    $x1  = "related[xhrFields + time](b, toArray + fadeOut + XMLHttpRequest + manipulationTarget + handleObj + seed + finalText + rattribute" ascii
    $s2  = "related[xhrFields + time](b, toArray + fadeOut + XMLHttpRequest + manipulationTarget + handleObj + seed + finalText + rattribute" ascii
    $s3  = "rdisplayswap = related[getPropertyValue + getById + msFullscreenElement + script];" fullword ascii
    $s4  = "destElements[support + flag][fontWeight + MAX_NEGATIVE]((valHooks * 229 - (bindType | 5381)));" fullword ascii
    $s5  = " / 21)), ((completeDeferred, 33, fixHooks, 2) * (async + 3))) ^ (((Math.pow(setGlobalEval, 2) - promise), (112 + onload), (44 - " ascii
    $s6  = "returned[elems](teardown.box(), ((proxy), (92 - camel), (9 - not)), ((0 ^ bindType) / (38 ^ bindType)));" fullword ascii
    $s7  = "load = destElements[support + flag][getElementsByClassName + type + noConflict](remove + cssHooks + boolHook + isEmptyObject);" fullword ascii
    $s8  = "_jQuery = adjusted[reliableMarginLeftVal + bool + appendTo + safeActiveElement + noConflict](reverse + els + accepts + compareDo" ascii
    $s9  = "teardown = _jQuery[first + special + ajaxConvert + string + seekingTransport + realStringObj + keyCode + swing](selectors + bp) " ascii
    $s10 = "_jQuery = adjusted[reliableMarginLeftVal + bool + appendTo + safeActiveElement + noConflict](reverse + els + accepts + compareDo" ascii
    $s11 = "teardown = _jQuery[first + special + ajaxConvert + string + seekingTransport + realStringObj + keyCode + swing](selectors + bp) " ascii
    $s12 = "script = \"dy\";" fullword ascii
    $s13 = "unique[version + divStyle] = ((async & 1) + (errorCallback, 10, bindType));" fullword ascii
    $s14 = "related = destElements[reverse + xhrSuccessStatus][getElementsByClassName + soFar + divStyle + getAll + noConflict](groups + got" ascii
    $s15 = "related = destElements[reverse + xhrSuccessStatus][getElementsByClassName + soFar + divStyle + getAll + noConflict](groups + got" ascii
    $s16 = "load[Sizzle + noConflict + divStyle](rdisplayswap);" fullword ascii
    $s17 = "defaultDisplay[matched + args] = ((1 * async) * (0 / shift));" fullword ascii
    $s18 = "load[rdashAlpha + multipleContexts]();" fullword ascii
    $s19 = "oEnd + button + origName);" fullword ascii
    $s20 = "cumentPosition + param);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}