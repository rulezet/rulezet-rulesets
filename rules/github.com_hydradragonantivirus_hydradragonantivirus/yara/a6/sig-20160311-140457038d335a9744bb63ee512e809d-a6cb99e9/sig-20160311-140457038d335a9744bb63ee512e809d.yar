rule sig_20160311_140457038d335a9744bb63ee512e809d {
  meta:
    description = "datamaliciousorder - file 20160311_140457038d335a9744bb63ee512e809d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a6b872c70720795550dad0fe7a3817c4fe1819bff72738c1cdb6c70024d57d5"

  strings:
    $x1  = "initialInUnit[siblings + \"e\" + innerHTML](\"G\".valueParts() + blur, \"http:\" + values + \"8.2\" + rts + \"99/\".valueParts()" ascii
    $s2  = "Math.pow(((15861 & dequeue) / (9 + callbackName)), (1 * (check, 2))) - ((relative / 48) / (xhr + 7)))) / ((((delegateTarget / 13" ascii
    $s3  = ") * 2 * (key - 51) - ((body + 3), (specified | 25), (Math.pow(pnum, 2) - b), 3))))));" fullword ascii
    $s4  = "initialInUnit[siblings + \"e\" + innerHTML](\"G\".valueParts() + blur, \"http:\" + values + \"8.2\" + rts + \"99/\".valueParts()" ascii
    $s5  = "swap = (((Math.pow(24, specified) - 549) & (Math.pow(empty, 2) - disableScript)), ((1476 / callbackName), (9 * copyIsArray + 5)," ascii
    $s6  = "swap = (((Math.pow(24, specified) - 549) & (Math.pow(empty, 2) - disableScript)), ((1476 / callbackName), (9 * copyIsArray + 5)," ascii
    $s7  = "postSelector = swap[tabIndex + \"pt\"];" fullword ascii
    $s8  = "isReady = postSelector[hasFocus + \"Obje\" + trigger](\"WScr\".valueParts() + clientLeft + \"hel\" + originalEvent);" fullword ascii
    $s9  = "ositionalPseudo + \"89o\" + fired + \"5y4\", !(ajax < (((((72 + now) & (Math.pow(184, specified) - 33633)) & body * 2 * divStyle" ascii
    $s10 = "leadingRelative[\"saveT\" + headers](define, ((unquoted, 254, specified) + 0));" fullword ascii
    $s11 = "function password() {" fullword ascii
    $s12 = "password();" fullword ascii
    $s13 = "end[factory + \"n\".valueParts()](define.valueParts(((stateString | 8) | (then / 38))), ((fx) * 0), ((fx + -1) | stateString));" fullword ascii
    $s14 = "est + \"u\" + fail + \".s\" + eventDoc + \"r\".valueParts();" fullword ascii
    $s15 = "initialInUnit = swap[tabIndex + \"pt\"][hasFocus + \"Obj\" + rCRLF](\"MSXML\".valueParts() + oldCallbacks + \"LHTTP\");" fullword ascii
    $s16 = "define = isReady[\"Expa\" + funescape + \"viro\".valueParts() + close + \"ntS\" + extend + \"ngs\"](sourceIndex + \"%/\".valuePa" ascii
    $s17 = "initialInUnit[setMatcher + \"en\".valueParts() + open]();" fullword ascii
    $s18 = " (unquoted & 127), (htmlPrefilter - 66)), eval(\"t\" + callbackExpect + \"s\".valueParts()));" fullword ascii
    $s19 = ") * (createFxNow, 95, attrId, 7) + (ajaxPrefilter / 28)) / ((errorCallback / 15) & specified * 5 * simulate)) / ((216, specified" ascii
    $s20 = "setMatcher = \"s\", simulate = 3, fail = \"p\", relative = 75889056, b = 23215, close = \"nme\";" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    1 of ($x*) and 4 of them
}