rule sig_20160307_51df81dc421913d937f92851ee2b5ad1 {
  meta:
    description = "datamaliciousorder - file 20160307_51df81dc421913d937f92851ee2b5ad1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1789b694fa31b083aebc606c5d48771a46d53fd1a24280fafb676645fb68aef2"

  strings:
    $s1  = "manipulationTarget[checked](innerHTML, rwhitespace + progress + oldCallbacks + hasScripts + postDispatch + stateString + image +" ascii
    $s2  = "while (manipulationTarget[createButtonPseudo + stopPropagation + version] < (Math.pow((clientX & 3), (eventPath | 0)) - (cssProp" ascii
    $s3  = "while (manipulationTarget[createButtonPseudo + stopPropagation + version] < (Math.pow((clientX & 3), (eventPath | 0)) - (cssProp" ascii
    $s4  = "manipulationTarget[elems + currentTarget + operator + genFx]();" fullword ascii
    $s5  = "disabled[filters + defaultValue + operator] = ((fail & 55) - (inspectPrefiltersOrTransports | 33));" fullword ascii
    $s6  = "manipulationTarget[checked](innerHTML, rwhitespace + progress + oldCallbacks + hasScripts + postDispatch + stateString + image +" ascii
    $s7  = "offset = conv[isXMLDoc + head + easing + pageY + checkNonElements + key + compile](defaultDisplay + elem) + createPositionalPseu" ascii
    $s8  = "offset = conv[isXMLDoc + head + easing + pageY + checkNonElements + key + compile](defaultDisplay + elem) + createPositionalPseu" ascii
    $s9  = "sel[makeArray + Deferred][tr + matchIndexes + overflowY](((createTween ^ 113) + (Math.pow(compareDocumentPosition, 2) - speeds))" ascii
    $s10 = "divStyle[preMap + htmlPrefilter + currentTarget](offset, ((eventPath + 0) & clientX));" fullword ascii
    $s11 = "sel[makeArray + Deferred][tr + matchIndexes + overflowY](((createTween ^ 113) + (Math.pow(compareDocumentPosition, 2) - speeds))" ascii
    $s12 = "manipulationTarget = sel[unqueued + cached + firstElementChild][transports + relative + firstElementChild + defaultExtra + _queu" ascii
    $s13 = "manipulationTarget = sel[unqueued + cached + firstElementChild][transports + relative + firstElementChild + defaultExtra + _queu" ascii
    $s14 = "divStyle = sel[idx + firstElementChild][escapedWhitespace + password + values + outerCache](keyCode + tr + rquery);" fullword ascii
    $s15 = "sel[subtract + until][checkOn + response + overflowY]((Math.pow((11287 - delay), (16 - col)) - (Math.pow(71510492, eventPath) - " ascii
    $s16 = "sel[subtract + until][checkOn + response + overflowY]((Math.pow((11287 - delay), (16 - col)) - (Math.pow(71510492, eventPath) - " ascii
    $s17 = " 2) - arg) & (4 | eventPath))) * ((1 * (cssProps | 0)) | ((load, 93, keyHooks, 237), (eventPath & 2)))))));" fullword ascii
    $s18 = "divStyle[visibility + operator]();" fullword ascii
    $s19 = "serializeArray[firstElementChild + globalEventContext + outermostContext] = (prop - 45);" fullword ascii
    $s20 = "concat = 27, load = 78, root = 103, _queueHooks = \"ect\", password = \"a\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}