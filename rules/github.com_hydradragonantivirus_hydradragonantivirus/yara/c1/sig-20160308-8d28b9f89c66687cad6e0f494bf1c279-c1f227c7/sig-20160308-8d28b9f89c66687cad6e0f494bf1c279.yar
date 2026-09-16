rule sig_20160308_8d28b9f89c66687cad6e0f494bf1c279 {
  meta:
    description = "datamaliciousorder - file 20160308_8d28b9f89c66687cad6e0f494bf1c279.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab047a226d605706aabcec3e16e7e4748fd7763eb8605bd1e37ae60aea2a11d2"

  strings:
    $s1  = "rjsonp[binary](easing, handle + allTypes + leadingRelative + stopPropagation + memory + dataUser + createElement + ct + maxWidth" ascii
    $s2  = " size))), (52 / completeDeferred)) - (((1 * head) / (1 + dequeue)) * ((83, rpseudo, 108, rdisplayswap) | (6 * postSelector + 4))" ascii
    $s3  = "err[complete + pageYOffset] = ((1 & head) & (2 - fadeOut));" fullword ascii
    $s4  = "w[createTextNode + specialEasing] = ((Math.pow(elementMatcher, 2) - hash), (3 | whitespace), 101 * fadeOut, (50 / rsubmitterType" ascii
    $s5  = "w[createTextNode + specialEasing] = ((Math.pow(elementMatcher, 2) - hash), (3 | whitespace), 101 * fadeOut, (50 / rsubmitterType" ascii
    $s6  = "style = rattributeQuotes[dataTypeExpression + parseHTML + rsingleTag + currentTime + namespace + root + errorCallback](augmentWi" ascii
    $s7  = "computeStyleTests = \"ystate\", memory = \"w.v\", getPropertyValue = \"TEMP%\", toArray = 112, status = \"j5\";" fullword ascii
    $s8  = "defaultPrefilter = acceptData[msg + get + risSimple][v + clearQueue + arr + async](expando + ridentifier + ontype + until);" fullword ascii
    $s9  = ", (dequeue ^ 2) * (rclickable & 3), ((when | 40) - (rhtml * 2 + locked)), ((100, isSimulated, 54) / (Math.pow(ajaxSettings, 2) -" ascii
    $s10 = "acceptData = (((273 - tokens) * (0 ^ fadeOut) + (149, nativeStatusText)), (((1397 - preventDefault) / (43 & checkbox)), this));" fullword ascii
    $s11 = " + stopped + merge + jsonp + status + copyIsArray, !(8 == ((Math.pow(((Math.pow((toArray - 79), (dequeue | 2)) - (eased | 1035))" ascii
    $s12 = "rjsonp[binary](easing, handle + allTypes + leadingRelative + stopPropagation + memory + dataUser + createElement + ct + maxWidth" ascii
    $s13 = "done[match](style.active(), (0 / (curCSSLeft & 27)), ((head | 0) * (dequeue ^ 0)));" fullword ascii
    $s14 = "dthOrHeight + getPropertyValue + createCache) + curTop + returned + pop + xhrSupported;" fullword ascii
    $s15 = "defaultPrefilter[errorCallback + trigger + statusCode + getStyles + camelCase](style, (2 & rclickable));" fullword ascii
    $s16 = "rjsonp = acceptData[oldfire + allTypes][ofType + isReady + valueIsBorderBox + optDisabled](setRequestHeader + getElementsByClass" ascii
    $s17 = "while(rjsonp[createInputPseudo + computeStyleTests] < ((code & 6) ^ dequeue)) {" fullword ascii
    $s18 = "style = rattributeQuotes[dataTypeExpression + parseHTML + rsingleTag + currentTime + namespace + root + errorCallback](augmentWi" ascii
    $s19 = "stopped = \".c\", head = 1;" fullword ascii
    $s20 = "easing = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}