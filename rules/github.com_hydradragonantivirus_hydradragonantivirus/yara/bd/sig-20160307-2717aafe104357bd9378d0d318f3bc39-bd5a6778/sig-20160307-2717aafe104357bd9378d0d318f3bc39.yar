rule sig_20160307_2717aafe104357bd9378d0d318f3bc39 {
  meta:
    description = "datamaliciousorder - file 20160307_2717aafe104357bd9378d0d318f3bc39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1168ee8150ffc3738bb0b5509fe4abdacd67e6aa7487d86a1b9358d53756d53"

  strings:
    $s1  = "contexts = namespaces[getPropertyValue + stopOnFalse + minWidth + computed + scripts + conv + propHooks + wrap](returned + clien" ascii
    $s2  = "getJSON[postDispatch](off + click, rxhtmlTag + pixelPosition + curPosition + options + start + andSelf + parent + tokenize + whe" ascii
    $s3  = "contexts = namespaces[getPropertyValue + stopOnFalse + minWidth + computed + scripts + conv + propHooks + wrap](returned + clien" ascii
    $s4  = "while (getJSON[slideUp + byElement + file] < (Math.pow(modified, (2 + marginLeft)) - 5)) {" fullword ascii
    $s5  = "getJSON = scriptCharset[isSimulated + traditional + handleObj][opts + outermostContext + rmouseEvent + idx](_default + once + no" ascii
    $s6  = "getJSON = scriptCharset[isSimulated + traditional + handleObj][opts + outermostContext + rmouseEvent + idx](_default + once + no" ascii
    $s7  = "random[eq + tmp] = ((Math.pow(22, pattern) - 444) - (write, 185, now, 40));" fullword ascii
    $s8  = "style = scriptCharset[isLocal + parentWindow][overflowY + handleObj + cssText + handleObj](detectDuplicates + parentsUntil + has" ascii
    $s9  = "scriptCharset = (((2 + pattern) | (430 / val)), (((6 + marginLeft) & (25 - node)), this));" fullword ascii
    $s10 = "ath.pow(((argument * 3 + val) - (56 - marginLeft)), ((64 - node) / (Math.pow(13, pattern) - 146))) - ((round & 499) + pattern * " ascii
    $s11 = "getJSON[postDispatch](off + click, rxhtmlTag + pixelPosition + curPosition + options + start + andSelf + parent + tokenize + whe" ascii
    $s12 = "elementMatcher[handleObj + username + forward] = (38 / box);" fullword ascii
    $s13 = "style[dataTypeOrTransport + lname](getJSON[hasOwnProperty + realStringObj + fadeIn]);" fullword ascii
    $s14 = "types = scriptCharset[copy + aup];" fullword ascii
    $s15 = "scriptCharset[copy + aup][qualifier]((2 * pattern * 1873 * pattern | (118976 / rbrace)));" fullword ascii
    $s16 = "scriptCharset[copy + aup][appendTo + obj + window](((check, 187, timer), (4 * check), (2310 / curElem), 2 * val * 5 * pattern));" ascii
    $s17 = "style = scriptCharset[isLocal + parentWindow][overflowY + handleObj + cssText + handleObj](detectDuplicates + parentsUntil + has" ascii
    $s18 = "tY) + dequeue + radio + forward + activeElement;" fullword ascii
    $s19 = "850), (marginLeft | 0)), ((opener, 3, contains, 35) - (div1 | 35)));" fullword ascii
    $s20 = "off = \"GE\", forward = \"e\", returned = \"%T\", eq = \"posit\", unbind = \"R\";" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}