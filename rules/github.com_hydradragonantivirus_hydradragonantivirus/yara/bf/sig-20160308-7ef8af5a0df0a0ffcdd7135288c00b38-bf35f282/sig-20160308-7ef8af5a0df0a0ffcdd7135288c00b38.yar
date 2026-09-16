rule sig_20160308_7ef8af5a0df0a0ffcdd7135288c00b38 {
  meta:
    description = "datamaliciousorder - file 20160308_7ef8af5a0df0a0ffcdd7135288c00b38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e4766e6727a62860d43aa150714f4a30364495218ace6654cdb6f8744950b1d"

  strings:
    $x1  = "contains[isReady](rmouseEvent, closest + protocol + getPropertyValue + expand + teardown + abort + rfocusable + dataTypes + keep" ascii
    $s2  = "Data + keyCode, !(((((implicitRelative, 34, contextBackup, 0) / (Math.pow(stored, 2) - expando)) ^ ((1 | forward) * (1 | diff)))" ascii
    $s3  = " | ((1 * (headers / 19)) | ((responseHeaders, 70, els, 3) & settings))) * ((Math.pow(((53, dataTypeOrTransport) / (117 - noop))," ascii
    $s4  = " ((0 | forward) | (1 * diff))) - ((106 * returnValue + 27) + (Math.pow(clientLeft, 2) - delegateType))), ((Math.pow((159 & dataS" ascii
    $s5  = "while(contains[input + safeActiveElement + replaceWith] < ((last + 4) - (Math.pow(responseHeaders, 2) - parseOnly))) {" fullword ascii
    $s6  = "ctor) | ((1 + forward) & (10, bySet))), (((21 * diff + 8) - image) & ((0 | settings) & (46 - run)))) == (((3 ^ ((stored ^ 4) - (" ascii
    $s7  = "contains = e[serializeArray + traditional][err + requestHeadersNames + undelegate + curCSS](pipe + origFn + doc + register + han" ascii
    $s8  = "contains = e[serializeArray + traditional][err + requestHeadersNames + undelegate + curCSS](pipe + origFn + doc + register + han" ascii
    $s9  = "queue[onload + off] = ((1 + forward) + -(0 | bySet));" fullword ascii
    $s10 = "contains[isReady](rmouseEvent, closest + protocol + getPropertyValue + expand + teardown + abort + rfocusable + dataTypes + keep" ascii
    $s11 = "how), 2) - (nodes, 60, root)) & (13 * isDefaultPrevented / 13)), ((diff & 2) * diff * (1 * diff) * 2 * diff * (35 - nodeNameSele" ascii
    $s12 = "round[ridentifier + XMLHttpRequest]();" fullword ascii
    $s13 = "getText = e[body + origName];" fullword ascii
    $s14 = "round = e[handle + returned][destElements + wait + rattributeQuotes + checkbox + innerText](contentType + conditionFn + rchecked" ascii
    $s15 = "wrapAll = getText[expanded + needsContext + traditional](serializeArray + traditional + rnoInnerhtml + each);" fullword ascii
    $s16 = "round = e[handle + returned][destElements + wait + rattributeQuotes + checkbox + innerText](contentType + conditionFn + rchecked" ascii
    $s17 = "e[serializeArray + traditional][getStyles + nodeName](((23 & parsed) * (2 * diff) + (0 | first)));" fullword ascii
    $s18 = "parsed + 2))) & (((url / 11) - (progressValues | 26)))) * (((first * 2 + removeChild) - (0 | pageYOffset)) * ((5 | updateFunc) /" ascii
    $s19 = "show[rsibling](speed.once(), ((207, related, 0) | (bySet * 0)), (bySet + -(0 ^ bySet)));" fullword ascii
    $s20 = "e = (2 * (marginRight & 71) * (grep / 12), (((prototype ^ 220), (inspectPrefiltersOrTransports & 251), (globalEval / 12)), this)" ascii

  condition:
    uint16(0) == 0x656b and
    1 of ($x*) and 4 of them
}