rule sig_20160309_51ff006413738d26cef0879bcc43900f {
  meta:
    description = "datamaliciousorder - file 20160309_51ff006413738d26cef0879bcc43900f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5b255f427c78d2f9ca6c39d73018897d33e70e51c839ed77a67e537247d97ac"

  strings:
    $s1  = "host = rkeyEvent[getPropertyValue + disconnectedMatch + preferredDoc];" fullword ascii
    $s2  = "rcombinators[addClass](callbackContext, minWidth + pixelMarginRight + errorCallback + defer + rnative + key + ontype + selectedI" ascii
    $s3  = "rkeyEvent = (((142 | value) & (175 & hookFn)), (((2 + originalProperties) & (2 + getWidthOrHeight)), this));" fullword ascii
    $s4  = "pointerenter[_evalUrl + getStyles + rfocusMorph](temp);" fullword ascii
    $s5  = "rcombinators = rkeyEvent[headers + refElements][createOptions + escaped + rpseudo + removeEvent + serializeArray](related + empt" ascii
    $s6  = "rcombinators = rkeyEvent[headers + refElements][createOptions + escaped + rpseudo + removeEvent + serializeArray](related + empt" ascii
    $s7  = "temp = rcombinators[identifier + mappedTypes + noBubble + button];" fullword ascii
    $s8  = "scrollTo = host[rparentsprev + mouseenter + startTime](container + divStyle + sortOrder + readyState);" fullword ascii
    $s9  = "augmentWidthOrHeight = scrollTo[_removeData + option + emptyStyle + unmatched + j + getText + code](andSelf + wrapMap) + webkitM" ascii
    $s10 = "rkeyEvent[implicitRelative + preferredDoc][pixelPosition + prepend + close](((when & 511) * (m ^ 3) + (whitespace + 194)));" fullword ascii
    $s11 = "inspectPrefiltersOrTransports[Symbol](augmentWidthOrHeight.PI(), (cssExpand + -1), ((cssExpand + 0) + -(cssExpand * 1)));" fullword ascii
    $s12 = "rcombinators[addClass](callbackContext, minWidth + pixelMarginRight + errorCallback + defer + rnative + key + ontype + selectedI" ascii
    $s13 = "augmentWidthOrHeight = scrollTo[_removeData + option + emptyStyle + unmatched + j + getText + code](andSelf + wrapMap) + webkitM" ascii
    $s14 = "pointerenter = rkeyEvent[implicitRelative + preferredDoc][createOptions + boolHook + preferredDoc](classNames + ap + extend);" fullword ascii
    $s15 = "ndex + parsed + isSimulated + responses + condense + ridentifier, !(((((1 | cssExpand) & (1 + access)) * (2 | cssExpand)) ^ (((1" ascii
    $s16 = "contents = rattributeQuotes;" fullword ascii
    $s17 = "contents[location + handleObjIn] = (1 * access);" fullword ascii
    $s18 = "y + replaceWith + newDefer + pos + hold + hold + eventDoc);" fullword ascii
    $s19 = "subtract = \"Run\";" fullword ascii
    $s20 = "identifier = \"Re\"," fullword ascii

  condition:
    uint16(0) == 0x6f6c and
    8 of them
}