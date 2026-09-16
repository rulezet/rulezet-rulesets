rule sig_20160307_a4b8b67d4dd462729373dc94fbcfeeb2 {
  meta:
    description = "datamaliciousorder - file 20160307_a4b8b67d4dd462729373dc94fbcfeeb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c041ff75377508354896a105bbda16e1d47f7d539751e973beec099d92f92e6"

  strings:
    $s1  = "list[doScroll](not, isXML + flag + defaultExtra + rnoContent + elemData + globalEventContext + lname, !(((((2 * setMatchers * 2 " ascii
    $s2  = "+ 1)) * (defaultView & 3) * (rheader ^ 2) * ((tick - 8) - (Math.pow(nodeNameSelector, 2) - setMatchers)) * ((44 + splice) / 5 * " ascii
    $s3  = "apply = (((3 ^ tokens) + (0 | rheader)), ((Math.pow((74, fcamelCase), (17 - tick)) - (265 + nodeNameSelector)), this));" fullword ascii
    $s4  = "bool = hover[count + fadeIn + hash + append + Callbacks + useCache](getWindow + disableScript + getWindow + showHide) + isPlainO" ascii
    $s5  = "bool = hover[count + fadeIn + hash + append + Callbacks + useCache](getWindow + disableScript + getWindow + showHide) + isPlainO" ascii
    $s6  = "jectWith + 8)) - ((elementMatcher + 1))), (((parseHTML - 13) + rheader) + 1)) - ((offset + 27), (rnumnonpx - 133), (defaultView " ascii
    $s7  = "while(list[byElement + rnamespace + getPropertyValue] < ((1 + -deepDataAndEvents) | (53, nodeNameSelector))) {" fullword ascii
    $s8  = "type = apply[getWidthOrHeight + responseText][letterSpacing + filters + rsingleTag + split](curLeft + _queueHooks + winnow);" fullword ascii
    $s9  = "list[doScroll](not, isXML + flag + defaultExtra + rnoContent + elemData + globalEventContext + lname, !(((((2 * setMatchers * 2 " ascii
    $s10 = "apply[matchAnyContext + outermostContext][cacheLength + eventHandle](((oldfire ^ 28604) - (version / 45)));" fullword ascii
    $s11 = "type[scrollTo + animation + triggered + binary](bool, (elementMatcher & 2));" fullword ascii
    $s12 = "type[requestHeaders]();" fullword ascii
    $s13 = "props[clearQueue + xhr] = ((toArray, 164, soFar, 0) / (filter / 24));" fullword ascii
    $s14 = "clientLeft = string + _data;" fullword ascii
    $s15 = "hover = makeArray[time + settings + msg + copy + originalProperties](clearTimeout + prefilterOrFactory + selectedIndex + once + " ascii
    $s16 = "type[nodes + animated]();" fullword ascii
    $s17 = "hover = makeArray[time + settings + msg + copy + originalProperties](clearTimeout + prefilterOrFactory + selectedIndex + once + " ascii
    $s18 = "version = 86895;" fullword ascii
    $s19 = "binary = \"le\";" fullword ascii
    $s20 = "type[rescape + checkbox](list[stopPropagation + etag + dataTypeOrTransport + step]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}