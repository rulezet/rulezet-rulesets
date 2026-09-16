rule sig_20160308_6c57e169f4bfce37b98da5f12878edf7 {
  meta:
    description = "datamaliciousorder - file 20160308_6c57e169f4bfce37b98da5f12878edf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b00cda9de5ac1f109b4b7b65575a8cef9d65d71ed65284d762586c1529d746bd"

  strings:
    $s1  = "access[pageYOffset](getScript + checkContext, useCache + progressValues + elements + deep + rnotwhite + dest + optDisabled + roo" ascii
    $s2  = "getElementsByTagName[location + JSON + swing + stopImmediatePropagation][source + swing](((Math.pow(10169, image) - 103394209) |" ascii
    $s3  = " getElementsByTagName[elementMatcher + clientY + view][source + swing](((curPosition / 29) + (start * 4 + hasContent)));" fullword ascii
    $s4  = ") * (Math.pow(3, image) - 4)) - (Math.pow(((createComment & 121) ^ (invert | 244)), ((image / 2) * (image & 3))) - (Math.pow((cu" ascii
    $s5  = "parseXML[oldCache + manipulationTarget + whitespace + getWindow + outermostContext](then, (3 * addToPrefiltersOrTransports * 5, " ascii
    $s6  = "parseXML[oldCache + manipulationTarget + whitespace + getWindow + outermostContext](then, (3 * addToPrefiltersOrTransports * 5, " ascii
    $s7  = "getElementsByTagName = (((1 * fadeToggle) | (162 - j)), (((4 * image + 1) ^ (guaranteedUnique * 0)), this));" fullword ascii
    $s8  = "getElementsByTagName[location + JSON + swing + stopImmediatePropagation][source + swing](((Math.pow(10169, image) - 103394209) |" ascii
    $s9  = "access[pageYOffset](getScript + checkContext, useCache + progressValues + elements + deep + rnotwhite + dest + optDisabled + roo" ascii
    $s10 = "t + Symbol + lang, !(remaining == (((((207, handleObj, 155, factory) + (Math.pow(26, image) - 643)) + image * (43 | currentValue" ascii
    $s11 = "round[postMap] = ((guaranteedUnique + 0) + (fadeToggle & 1));" fullword ascii
    $s12 = "access[emptyGet + _load]();" fullword ascii
    $s13 = "parseXML = getElementsByTagName[risSimple + createPseudo][ajaxSetup + matchers + href](tween + reset + timers + pattern);" fullword ascii
    $s14 = "rLeft ^ 24884), image) - 685156340))) / (((guaranteedUnique + -1) | (guaranteedUnique * 1)) | (((nodeType + 2) & (wrapInner - 10" ascii
    $s15 = "access = getElementsByTagName[location + needsContext + stopImmediatePropagation][cache + tokens + dataTypes](querySelectorAll +" ascii
    $s16 = "access = getElementsByTagName[location + needsContext + stopImmediatePropagation][cache + tokens + dataTypes](querySelectorAll +" ascii
    $s17 = "then = ignored[amd + responseContainer + preventDefault + accepts + open + _$ + soFar](fail + setAttribute + reliableMarginLeft)" ascii
    $s18 = "then = ignored[amd + responseContainer + preventDefault + accepts + open + _$ + soFar](fail + setAttribute + reliableMarginLeft)" ascii
    $s19 = ")) * ((related + 17), (addToPrefiltersOrTransports & 5)) + ((image ^ 7) + (fadeToggle ^ 0)))))));" fullword ascii
    $s20 = "while (access[w + type + completeDeferred] < (callbackInverse - 36) * (emptyStyle, 2)) {" fullword ascii

  condition:
    uint16(0) == 0x534a and
    8 of them
}