rule sig_20160308_26d1c2f8e53748834c78556f95a5de60 {
  meta:
    description = "datamaliciousorder - file 20160308_26d1c2f8e53748834c78556f95a5de60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcaba68f2319fcb0bc34f234e36ffa302df9d12031cca42aacea3b11bc91bb6f"

  strings:
    $s1  = "options[slideUp + defaultValue](len, manipulationTarget + scrollLeft + unquoted + percent + onreadystatechange + remove + width " ascii
    $s2  = "options[slideUp + defaultValue](len, manipulationTarget + scrollLeft + unquoted + percent + onreadystatechange + remove + width " ascii
    $s3  = ")) * ((Math.pow(((4 + origName) ^ (120 / addGetHookIf)), 2) - ((queue & 117) ^ (closest & 29))), ((events & (1 | removeData)) & " ascii
    $s4  = "while (options[scripts + raw + maxIterations] < ((rprotocol / 1), (statusCode - 21))) {" fullword ascii
    $s5  = "tokens = \"Crea\", condense = \"positi\", overwritten = \"at\", manipulationTarget = \"h\", xhrSuccessStatus = \"leep\";" fullword ascii
    $s6  = "  htmlPrefilter[rclass + high][tabIndex + onreadystatechange]((Math.pow((matchExpr ^ 122), origName) - (12768 / onlyHandlers)));" ascii
    $s7  = "elemLang[stop](b.eventPath(), ((offsetWidth & 1) + -(getComputedStyle - 16)), ((offsetWidth * 0) ^ (toggleClass | 0)));" fullword ascii
    $s8  = " * offsetWidth)) ^ ((1 + -(focus - 23)) & ((Math.pow(offset, 2) - updateFunc), 79 * origName, (162 | params), (1 | offsetWidth))" ascii
    $s9  = "match[raw + completeDeferred + cssText + matcherIn](b, ((removeChild / 45) - (context & 58)));" fullword ascii
    $s10 = "match[slideUp + postSelector + remove]();" fullword ascii
    $s11 = "htmlPrefilter = (((101 | responseText), (1806 / defaultView), (26 * properties + 1)), (((attrs - 32), (focus - 11)), this));" fullword ascii
    $s12 = "b = dataFilter[inArray + setTimeout + slideUp + remove + bubbleType + elements + ajaxHandleResponses + remove + detach + raw](or" ascii
    $s13 = "iginalOptions + attrId + nonce) + i + overflowY + ajaxTransport + high + _$ + result;" fullword ascii
    $s14 = "options = htmlPrefilter[rclass + high][parsed + completeDeferred + cur + rdisplayswap + high](key + dataAttr + returnTrue + star" ascii
    $s15 = "match = htmlPrefilter[dirrunsUnique + onreadystatechange + high][tokens + dataUser + always + callbackName + high](shift + _load" ascii
    $s16 = "dataFilter = scale[parsed + overwritten + cloneNode + pageY](xhrSupported + option + onreadystatechange + easing + code);" fullword ascii
    $s17 = "options = htmlPrefilter[rclass + high][parsed + completeDeferred + cur + rdisplayswap + high](key + dataAttr + returnTrue + star" ascii
    $s18 = "match = htmlPrefilter[dirrunsUnique + onreadystatechange + high][tokens + dataUser + always + callbackName + high](shift + _load" ascii
    $s19 = "htmlPrefilter[uniqueSort + callbackName + hold][getAllResponseHeaders + xhrSuccessStatus](((3314 ^ cssFn)));" fullword ascii
    $s20 = "stop = indirect + selector;" fullword ascii

  condition:
    uint16(0) == 0x7075 and
    8 of them
}