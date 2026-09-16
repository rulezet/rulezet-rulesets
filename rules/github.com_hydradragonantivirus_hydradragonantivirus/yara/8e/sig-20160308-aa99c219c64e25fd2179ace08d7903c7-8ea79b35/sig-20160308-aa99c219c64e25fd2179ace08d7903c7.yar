rule sig_20160308_aa99c219c64e25fd2179ace08d7903c7 {
  meta:
    description = "datamaliciousorder - file 20160308_aa99c219c64e25fd2179ace08d7903c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec672c1c9adf6b797026329cbe3a3f090646ef68cbe3d4a9ef9f88d3e17866d0"

  strings:
    $x1  = "prototype[propName](swing, set + size + contentType + opt + hidden + parent + addToPrefiltersOrTransports + Expr + each, !((((((" ascii
    $s2  = "(0 / proxy))) - (Math.pow(((Math.pow(777, bySet) - 602481) / getWindow * 2 * bySet * 2 * bySet), ((1 | content) + (1 | els))) - " ascii
    $s3  = "display = ((Math.pow((24 * speeds + 7), (content + 1)) - (pdataCur - 9241)), (((tmp + 4) & (writable)), this));" fullword ascii
    $s4  = "3 ^ newSelector) * 2 + (proxy / 5)) & ((uniqueID / 27) | (reverse & 43))) + ((Math.pow((elemdisplay & 5), (content + 1)) - (elem" ascii
    $s5  = "prototype[propName](swing, set + size + contentType + opt + hidden + parent + addToPrefiltersOrTransports + Expr + each, !((((((" ascii
    $s6  = "- 29)) | (Math.pow(((subordinate + 4) & (matcher / 15)), ((hooks, 182, getWindow) & (1 * bySet))) - ((13006 / childNodes))))) ==" ascii
    $s7  = " (Math.pow((((1 + (pattern, 226, boxSizingReliable, 0)) & ((Math.pow(readyList, 2) - andSelf) / (95 - defaultDisplay))) * (((29 " ascii
    $s8  = "rheaders[xhrFields + queue + fn] = ((els ^ 0) / (writable - 9));" fullword ascii
    $s9  = "while (prototype[gotoEnd + returnTrue + divStyle + getStyles] < ((39 - risSimple) * (20, bySet))) {" fullword ascii
    $s10 = "display[checked + nonce + mapped + result + msMatchesSelector][toArray]((Math.pow((Math.pow(camelKey, 2) - len), (0 | bySet)) - " ascii
    $s11 = "display + 7)) & ((content * 0) | (elemdisplay & 7)))) - (((fire & (88 - classCache)) ^ (Math.pow((43 - risSimple), (1 * bySet)) " ascii
    $s12 = " bySet) - 7029347) / (childNodes + 3)), ((writable + 17) - (Math.pow(hasClass, 2) - getter)))))));" fullword ascii
    $s13 = " + support + requestHeaders + requestHeadersNames);" fullword ascii
    $s14 = "prototype = display[checked + markFunction + msMatchesSelector][webkitMatchesSelector + stopOnFalse + newContext + ontype](abort" ascii
    $s15 = "((rcssNum ^ 242), firstDataType * 3, (binary | 11), (stopImmediatePropagation | 6148)) / ((token | 36) ^ (els ^ 0))), (((bySet ^" ascii
    $s16 = "display[checked + nonce + mapped + result + msMatchesSelector][toArray]((Math.pow((Math.pow(camelKey, 2) - len), (0 | bySet)) - " ascii
    $s17 = "groups[host + notifyWith](noop, ((content) * (2 ^ els)));" fullword ascii
    $s18 = "- subordinate) | (87, eventDoc, 5)) & ((els | 5) ^ (els)))), ((((4 | getElementsByClassName) ^ (33 - overflowX)) ^ ((1 | els) ^ " ascii
    $s19 = "outerCache[ofType](noop.callbackInverse(), ((49 - doAnimation) ^ (0 ^ els)), ((1 & content) + -(1 & content)));" fullword ascii
    $s20 = "noop = setTimeout[jsonProp + matchIndexes + cos + readyState + removeClass + computeStyleTests + dataUser](hover + attachEvent +" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}