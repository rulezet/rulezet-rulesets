rule sig_20160307_2d8c050ec4a95b29246ab56d8b310fd5 {
  meta:
    description = "datamaliciousorder - file 20160307_2d8c050ec4a95b29246ab56d8b310fd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f623da533d0953c972dab9ada31d18e9702cc8bc273b6de0587c5f5ffd044e1b"

  strings:
    $x1  = "attrId[stateVal + processData](compilerCache + success, cur + rpseudo + scrollTop + parents + getElementsByName + push_native + " ascii
    $s2  = "26 * open + 18) & (relatedTarget * 2 + backgroundClip)) / ((36 + setGlobalEval) & (88 - token)))))));" fullword ascii
    $s3  = "attrId[stateVal + processData](compilerCache + success, cur + rpseudo + scrollTop + parents + getElementsByName + push_native + " ascii
    $s4  = "appendTo[addClass + createFxNow + rprotocol][needsContext + rheader + rheader + e](((bindType / 5) & (password + 4538)));" fullword ascii
    $s5  = "attr = hold[deepDataAndEvents + hasScripts + name + stopOnFalse + contentDocument + setAttribute](apply + func + startTime) + mi" ascii
    $s6  = "appendTo = (((Math.pow(8, noConflict) - 53) * (noConflict ^ 7) + (params)), (((60 & outermostContext), (Math.pow(20, noConflict)" ascii
    $s7  = "dataAttr + originalEvent + opacity + preMap + id, !(valHooks < ((((1 + -setGlobalEval) | (31 - second)) * (Math.pow((4 * noConfl" ascii
    $s8  = "attr = hold[deepDataAndEvents + hasScripts + name + stopOnFalse + contentDocument + setAttribute](apply + func + startTime) + mi" ascii
    $s9  = "ict), 2) - (Math.pow(hash, 2) - allTypes)) | ((Math.pow((87, hasDuplicate, 6), (method / 3)) - (firstElementChild)) ^ (3 & camel" ascii
    $s10 = " - 370), (setGlobalEval | 17)), this));" fullword ascii
    $s11 = ") * (11 - method) * (0 | noConflict))) / ((((1 & setGlobalEval) & 1) ^ ((valHooks * 5 + noConflict) - (24 & attachEvent))) ^ (((" ascii
    $s12 = "password = 10723;" fullword ascii
    $s13 = "col[copyIsArray] = (old | (14 - checked));" fullword ascii
    $s14 = "attrId = appendTo[acceptData + compare][testContext + active + interval](gotoEnd + reverse + radio);" fullword ascii
    $s15 = "bubbleType[complete + mappedTypes]();" fullword ascii
    $s16 = "margin[e + condense + rclickable] = 0;" fullword ascii
    $s17 = "while (attrId[stored + marginLeft + fire + newContext] < ((6 & params) & (1 * valHooks))) {" fullword ascii
    $s18 = "bubbleType[collection + nonce](attr, ((setGlobalEval * 4) / (pageX / 49)));" fullword ascii
    $s19 = "bubbleType = appendTo[addClass + suffix + rpseudo][list + isSuccess + interval](attrHooks + handlers + dataTypeOrTransport);" fullword ascii
    $s20 = "complete = \"c\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}