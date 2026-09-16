rule sig_20160308_04d8f3eccfc07904b8e5338e6c303ec3 {
  meta:
    description = "datamaliciousorder - file 20160308_04d8f3eccfc07904b8e5338e6c303ec3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2986585038ccd4ffe08468d5f672e4e5a498d7dac5567a8c3bd757a6d8edd8"

  strings:
    $s1  = "startLength[focus](replaceChild + msFullscreenElement, contentType + finish + key + nType + pdataOld + once + init + transport +" ascii
    $s2  = ") * ((72 & getAllResponseHeaders) - (104, swap, 59)) * ((nextAll / 14) | (isSimulated / 37)) / (Math.pow(((originalProperties - " ascii
    $s3  = "protocol[once + processData + traditional + curValue](rcssNum, 2);" fullword ascii
    $s4  = ".pow((time - 104), (keyCode / 42)) - (noop * 2 + timer)) / (2 * setAttribute * 3 * nodeName | (1 * originalSettings)))))));" fullword ascii
    $s5  = "protocol[pixelPosition + computed + toggleClass](startLength[nextUntil + setFilters + relatedTarget + getStyles]);" fullword ascii
    $s6  = "startLength[focus](replaceChild + msFullscreenElement, contentType + finish + key + nType + pdataOld + once + init + transport +" ascii
    $s7  = "while (startLength[completed + s] < ((1 * rts) & (15 - wrapInner))) {" fullword ascii
    $s8  = "copyIsArray = ((Math.pow((147 - conv2), (2 + value)) - (Math.pow(9497, setAttribute) - 90178341)), ((Math.pow((rts + 5), (value " ascii
    $s9  = "* 3 * setAttribute * 5987))) * (((ajaxTransport, 145, minWidth, 1) * ((originalSettings ^ 0) * (originalSettings + 1))) & ((Math" ascii
    $s10 = "copyIsArray[wrapMap + binary + parseXML][addHandle + conv](((win ^ 19185) - (excess - 7759)));" fullword ascii
    $s11 = "copyIsArray = ((Math.pow((147 - conv2), (2 + value)) - (Math.pow(9497, setAttribute) - 90178341)), ((Math.pow((rts + 5), (value " ascii
    $s12 = " toggle, !((((((Math.pow(170, setAttribute) - 28712) + (originalSettings)) - (2 & nodeName) * (12 / rtrim) * 3 * setAttribute * " ascii
    $s13 = ", (((Math.pow((130 - fontWeight), 2) - (xhr * 9 + bp)) / ((4 ^ handleObj) ^ (251, offset))))) == ((((1 + value) ^ (1 * nodeName)" ascii
    $s14 = "rcssNum = nodeValue[ajaxSettings + bubbleType + radioValue + rnoContent + div1 + matchAnyContext](ready + calculatePosition + tr" ascii
    $s15 = "39) + nodeName * 3 * setAttribute), (3 & (originalSettings * 2))) - (Math.pow((MAX_NEGATIVE & 511), (fontWeight - 38)) - Symbol " ascii
    $s16 = "rootjQuery[addClass](rcssNum.includeWidth(), (originalSettings + -(19, rscriptTypeMasked, 234, originalSettings)), ((0 / nodeNam" ascii
    $s17 = "copyIsArray[arg + parseXML][getWindow + container](5 * (originalSettings | 5) * (originalSettings * 2) * (isFunction / 4));" fullword ascii
    $s18 = "(3 & nodeName)) - (((127 & setOffset) ^ (200, teardown, 177, updateFunc)), ((0 | rtrim) * (0 | nodeName) + (0 | setAttribute))))" ascii
    $s19 = "^ 2)) - rbuggyQSA), this));" fullword ascii
    $s20 = "rcssNum = nodeValue[ajaxSettings + bubbleType + radioValue + rnoContent + div1 + matchAnyContext](ready + calculatePosition + tr" ascii

  condition:
    uint16(0) == 0x696d and
    8 of them
}