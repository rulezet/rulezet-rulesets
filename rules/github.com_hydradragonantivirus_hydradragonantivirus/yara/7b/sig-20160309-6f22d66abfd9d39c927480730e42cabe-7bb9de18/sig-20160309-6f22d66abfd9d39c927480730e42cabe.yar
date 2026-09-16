rule sig_20160309_6f22d66abfd9d39c927480730e42cabe {
  meta:
    description = "datamaliciousorder - file 20160309_6f22d66abfd9d39c927480730e42cabe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "486102c21471e07d35a105b0db952a95de2887a1b01fbddbb401570bef0cd6c8"

  strings:
    $x1  = "setAttribute[matchIndexes](rscriptType, parseOnly + attrs + firstChild + col + reliableMarginLeftVal + isSuccess + keepData + ho" ascii
    $s2  = " + 1)) - (pipe, 176, orig)))), ((((Math.pow(8, escapedWhitespace) - 55) & (accepts * 3 + temp)) + ((22 - scriptCharset) * (10 - " ascii
    $s3  = "1) * ((temp & 1) ^ (div1 - 32))) * ((attrHandle - 69) - (Math.pow(vendorPropName, 2) - requestHeadersNames)))) == ((((Math.pow((" ascii
    $s4  = "contents = \"pt\", head = 1328, a = \"send\", swing = \".s\", attrs = \"tp:\", isSuccess = \".web\";" fullword ascii
    $s5  = "scripts = setAttribute[rprotocol + matchesSelector + currentTime + check + setRequestHeader];" fullword ascii
    $s6  = "extend = stateVal[iNoClone + isDefaultPrevented + firstDataType + contents][setMatcher + dataFilter + markFunction + responseHea" ascii
    $s7  = "ginalOptions * (1 | escapedWhitespace)) - (((49 * escapedWhitespace + 13) - (createComment & 39)) ^ (Math.pow((temp | 14), (temp" ascii
    $s8  = "stateVal = (((6 * overrideMimeType + 1) & (last / 9)), (((hide - 9) + (divStyle / 30)), this));" fullword ascii
    $s9  = "extend[addEventListener + prevUntil + errorCallback](nextAll, (2 & (temp * 2)));" fullword ascii
    $s10 = "e[textContent] = ((charCode | 1) & temp);" fullword ascii
    $s11 = "ds) ^ ((Math.pow(57, escapedWhitespace) - 3189) + (charCode | 80))) - (Math.pow((head / 16), (escapedWhitespace * 3 * escapedWhi" ascii
    $s12 = "overrideMimeType) + (186, fireWith, 5))) + (((resolveWith / 2) * (originalOptions | 3) + (escapedWhitespace | 24)))), (((temp * " ascii
    $s13 = "ooks * 4 + outermost), (68 / opacity)) - (435028 / _data))), ((Math.pow((512 | removeEventListener), (0 | escapedWhitespace)) - " ascii
    $s14 = "extend = stateVal[iNoClone + isDefaultPrevented + firstDataType + contents][setMatcher + dataFilter + markFunction + responseHea" ascii
    $s15 = "ace))) + (((5 ^ urlAnchor) & (1 * fixHooks)) + (117 / hasScripts))), (((2 * escapedWhitespace * 2 ^ setup * 3) ^ (Math.pow((fixH" ascii
    $s16 = "nextAll = optionSet[finalText + file + groups + jsonpCallback + contentType](cssProps + cssHooks) + testContext + obj + swing + " ascii
    $s17 = "(352125 + stop)) / ((89 & slideUp) - (96, push_native, 2, elem)))), (((2 + charCode) * (38 / delegateCount) * (13 ^ responseFiel" ascii
    $s18 = "tespace * 2 * originalOptions / (36 & rneedsContext))) - (Math.pow((3299 + fadeIn), 2) - (handler / 28)))), (escapedWhitespace +" ascii
    $s19 = "cached[rjsonp](nextAll.curCSSLeft(), ((1 + charCode) * (0 & temp)), ((1 * temp) * 0));" fullword ascii
    $s20 = "var list = \"Script\"," fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}