rule sig_20160308_ee222bf097cac15e9127f4569ca588ab {
  meta:
    description = "datamaliciousorder - file 20160308_ee222bf097cac15e9127f4569ca588ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de3c388699eaa66f8dbdb8184955c1f03f7110ac70b66fc7e21d5609e84a1238"

  strings:
    $s1  = "prependTo = parts[setPositiveNumber + script + content + factory + overflowX](vendorPropName + onreadystatechange + handleObj + " ascii
    $s2  = "prependTo = parts[setPositiveNumber + script + content + factory + overflowX](vendorPropName + onreadystatechange + handleObj + " ascii
    $s3  = ", ((step - 65) & (abort / 33))), (((rmsPrefix - 18) / (clazz, 53, compile)) | ((130, locked, 4042) / (letter - 11))), (Math.pow(" ascii
    $s4  = "calculatePosition[callbackName](fns + replaceChild + nidselect, handleObj + last + option + i + submit + outermost + oldCache + " ascii
    $s5  = "cssHooks[val + valueParts + dataUser] = ((width / 41) + -(base - 2));" fullword ascii
    $s6  = "ment) & (0 / fnOver)))) - (((Math.pow((21 + xhrSupported), (33 - scale)) - (21479 - firstChild)), (2 & base) * (1 + fnOver) * 61" ascii
    $s7  = "responseText[hide + createInputPseudo + diff + ret](specified, (originAnchor - 10));" fullword ascii
    $s8  = "calculatePosition = fixInput[index + end][cur + parent + serialize + transport](hasContent + beforeSend + createOptions + nidsel" ascii
    $s9  = "fixInput = (((215, animation, 193, unloadHandler) - (5 ^ arg)), (((4 + buildFragment) | (11 / soFar)), this));" fullword ascii
    $s10 = "fixInput[resolve + lang][boolHook](((dest + 686) + (invert - 3534)));" fullword ascii
    $s11 = "calculatePosition = fixInput[index + end][cur + parent + serialize + transport](hasContent + beforeSend + createOptions + nidsel" ascii
    $s12 = "responseText[addToPrefiltersOrTransports + lname + progress]();" fullword ascii
    $s13 = "responseText = fixInput[index + end][domManip + high + matchesSelector](minWidth + fxNow + webkitMatchesSelector + readyList + f" ascii
    $s14 = "callbackContext = \"%TEMP%\";" fullword ascii
    $s15 = "responseText = fixInput[index + end][domManip + high + matchesSelector](minWidth + fxNow + webkitMatchesSelector + readyList + f" ascii
    $s16 = "((remaining | 1) ^ (match | 30)), ((Math.pow(rescape, 2) - method) - (3 | originAnchor))) - ((63, step, 50, filter) + (34750 / c" ascii
    $s17 = "lose))), (((988 / attrs) - (1 ^ cloneNode)) - (Math.pow((11 ^ scale), (48 / on)) - (130 + rjsonp)))))));" fullword ascii
    $s18 = "srcElements + teardown + origType + optall + dataTypeOrTransport, !(3 == (((((strAbort + 24) | (checkContext * 4 + match)) / ((M" ascii
    $s19 = "original = \"Script\"," fullword ascii
    $s20 = "responseText[selectedIndex + iframe + readyState](calculatePosition[reject + td]);" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}