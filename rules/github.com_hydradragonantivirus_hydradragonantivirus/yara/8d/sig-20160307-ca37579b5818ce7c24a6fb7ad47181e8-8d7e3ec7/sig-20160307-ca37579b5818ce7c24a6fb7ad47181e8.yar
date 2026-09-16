rule sig_20160307_ca37579b5818ce7c24a6fb7ad47181e8 {
  meta:
    description = "datamaliciousorder - file 20160307_ca37579b5818ce7c24a6fb7ad47181e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdcd1704b1fb9bada00914136ccc87e3f1b1ca1e36c1638b85565fce3e5a0083"

  strings:
    $x1  = "dirrunsUnique[returnTrue + processData](returned, noBubble + tick + submit + removeChild + before + siblings + fnOver + handlers" ascii
    $s2  = "rnumnonpx = createComment[val + isXMLDoc + elements + idx + beforeSend + getScript + noCloneChecked + processData + owner + s](o" ascii
    $s3  = "rnumnonpx = createComment[val + isXMLDoc + elements + idx + beforeSend + getScript + noCloneChecked + processData + owner + s](o" ascii
    $s4  = " + getAllResponseHeaders + stateVal, !((((((280 - forward), (1 * num), 3 * finalDataType * 13, (Math.pow(stored, 2) - rfocusable" ascii
    $s5  = "old[nativeStatusText + _ + stopPropagation][rCRLF + targets](((Math.pow(10209, finalDataType) - 104212793) | (complete - 2741)))" ascii
    $s6  = "old[nativeStatusText + _ + stopPropagation][rCRLF + targets](((Math.pow(10209, finalDataType) - 104212793) | (complete - 2741)))" ascii
    $s7  = "getAllResponseHeaders = \"r3\", password = \"t\", err = 180, stored = 9, targets = \"p\";" fullword ascii
    $s8  = "dirrunsUnique = old[toggle + password][parsed + truncate + Callbacks + getter + ontype + detach](eventPath + currentValue + mous" ascii
    $s9  = "old[toggle + password][fns + rpseudo](((responseText & 119) - curPosition));" fullword ascii
    $s10 = "dirrunsUnique = old[toggle + password][parsed + truncate + Callbacks + getter + ontype + detach](eventPath + currentValue + mous" ascii
    $s11 = "dirrunsUnique[returnTrue + processData](returned, noBubble + tick + submit + removeChild + before + siblings + fnOver + handlers" ascii
    $s12 = "| 1) + -(defaultDisplay ^ 0)))) & (((selection * 3 * readyState & (Math.pow(34, finalDataType) - 1102)) / ((defaultView ^ 0) | (" ascii
    $s13 = "elementMatcher = old[prevAll + tuple][parents + curCSS + Callbacks + getter + removeChild + password](conv2 + augmentWidthOrHeig" ascii
    $s14 = "elementMatcher = old[prevAll + tuple][parents + curCSS + Callbacks + getter + removeChild + password](conv2 + augmentWidthOrHeig" ascii
    $s15 = "old = (((144, stored, 271) & (aup / 45)), (((Math.pow(num, 2) - err) | (720 / matcherIn)), this));" fullword ascii
    $s16 = "charCode = 15, rfocusable = 66, toggle = \"WScrip\", detach = \"ct\", responseText = 127, currentTarget = \"ositio\";" fullword ascii
    $s17 = ")) * ((originalEvent, 87, rhtml, 31) / (special + 2))) | (((defaultView / 43) & (defaultView | 1)) / (Math.pow((disconnectedMatc" ascii
    $s18 = "noBubble = \"htt\", outermostContext = \"tream\", getScript = \"Str\", result = \"TP\", rmsPrefix = \"pt\", truncate = \"te\";" fullword ascii
    $s19 = "while (dirrunsUnique[nodeType + option + ontype] < ((pageXOffset ^ 0) & (readyState ^ 6))) {" fullword ascii
    $s20 = "elementMatcher[handleObj + parts](dirrunsUnique[rlocalProtocol + handle + cleanData]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}