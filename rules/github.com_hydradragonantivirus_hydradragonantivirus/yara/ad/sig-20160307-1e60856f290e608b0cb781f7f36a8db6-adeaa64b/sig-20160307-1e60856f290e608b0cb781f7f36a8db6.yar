rule sig_20160307_1e60856f290e608b0cb781f7f36a8db6 {
  meta:
    description = "datamaliciousorder - file 20160307_1e60856f290e608b0cb781f7f36a8db6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8ca5090d7ec1ca086d585a1a9a1dc7588d75615a4f86b8fe969cd34878d552b"

  strings:
    $x1  = "getWindow[r20](protocol, offsetParent + _load + hover + contents + fix + parseXML + xhrSuccessStatus + firstElementChild + ajaxS" ascii
    $s2  = "triggerHandler[originAnchor + conv2][rnoContent](((fast + 44) ^ (Math.pow(swing, 2) - hasScripts)));" fullword ascii
    $s3  = "getWindow[r20](protocol, offsetParent + _load + hover + contents + fix + parseXML + xhrSuccessStatus + firstElementChild + ajaxS" ascii
    $s4  = "memory = invert[qualifier + optall + type + filters + rheaders + close + dataPriv](pseudos + contents) + rclickable + sortOrder " ascii
    $s5  = "memory = invert[qualifier + optall + type + filters + rheaders + close + dataPriv](pseudos + contents) + rclickable + sortOrder " ascii
    $s6  = "getWindow = triggerHandler[rhtml + nidselect + conv2][createTextNode + obj + mouseleave + high + exports + th](param + requestHe" ascii
    $s7  = "getWindow = triggerHandler[rhtml + nidselect + conv2][createTextNode + obj + mouseleave + high + exports + th](param + requestHe" ascii
    $s8  = "etup + rwhitespace, !((((((48, inPage) - (Math.pow(35, matchedCount) - 1181)) | ((matchedCount * 2 + progress) * (1 * JSON) + (8" ascii
    $s9  = "firstElementChild = \"com/76\", fireGlobals = \"t.She\", rheaders = \"ment\", trigger = \"e\", delegateType = 36;" fullword ascii
    $s10 = "var pseudos = \"%TEMP%\"," fullword ascii
    $s11 = "while(getWindow[jqXHR + returned + obj] < ((22 ^ split) / 23)) {" fullword ascii
    $s12 = "responseHeaders[getter + jqXHR + argument + th + trigger](getWindow[animate + cleanData + setMatched + blur]);" fullword ascii
    $s13 = "responseHeaders[innerHTML + removeChild + s + trigger](memory, ((46 * matchedCount + 12), (notify & 255), (opt + 84), (appendTo " ascii
    $s14 = "responseHeaders[innerHTML + removeChild + s + trigger](memory, ((46 * matchedCount + 12), (notify & 255), (opt + 84), (appendTo " ascii
    $s15 = "7, notify, 9, scrollLeft))) | ((2 * matchedCount * 2 * matchedCount * 2 - (currentTime + 15)) - ((pop / 10) + (appendTo & 1)))) " ascii
    $s16 = "triggerHandler = (((14 & cloneCopyEvent) + (6 | prependTo)), (((17 - handler)), this));" fullword ascii
    $s17 = "responseHeaders = triggerHandler[fcamelCase + define][addEventListener + time + th](top + input + maxWidth + implementation);" fullword ascii
    $s18 = "self[destElements] = ((1 * progress) | (1 + -progress));" fullword ascii
    $s19 = "preferredDoc = \"er\", hasScripts = 2408, filters = \"on\", swing = 50;" fullword ascii
    $s20 = "self = responseHeaders;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}