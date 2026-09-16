rule sig_20160329_32782eb601bd614d8c035c5f4a95ba49 {
  meta:
    description = "datamaliciousorder - file 20160329_32782eb601bd614d8c035c5f4a95ba49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffa472870cc631e2f7c6391669b4f27e0d2fc0f9f71a5fce836be023782c6dc"

  strings:
    $s1  = "if(handleObjIn[ajaxSetup] == (2 * (relatedTarget / 14) * (cloneNode - 27) * (then, 242, parts, 5) * (each / 44))) {" fullword ascii
    $s2  = "complete(\"factory%20%3D%20%5BgetElementsByClassName%20+%20%22l2.Se%22%20+%20defaultPrefilter%20+%20%22rXMLHT%22%20+%20one%2C%20" ascii
    $s3  = "complete(\"overrideMimeType%20%3D%20pattern%5BoverflowY%20+%20%22pt%22%5D%5BrequestHeadersNames%20+%20%22Obj%22%20+%20memory%5D%" ascii
    $s4  = "complete(\"overrideMimeType%20%3D%20pattern%5BoverflowY%20+%20%22pt%22%5D%5BrequestHeadersNames%20+%20%22Obj%22%20+%20memory%5D%" ascii
    $s5  = "complete(\"overrideMimeType%5B%22mo%22%20+%20Data%20+%20%22e%22%5D%20%3D%20%28%283*len%29-%2811+get%29%29%3B\");" fullword ascii
    $s6  = "overrideMimeType[\"SaveT\" + pixelPosition + \"e\"](preferredDoc, ((trigger, 167, parts) + (0 & isReady)));" fullword ascii
    $s7  = "complete(\"while%20%28handleObjIn%5B%22readyS%22%20+%20responseHeaders%20+%20%22e%22%5D%20%21%3D%20%28%281*parts%29+2%29%29%20pa" ascii
    $s8  = "complete(\"while%20%28handleObjIn%5B%22readyS%22%20+%20responseHeaders%20+%20%22e%22%5D%20%21%3D%20%28%281*parts%29+2%29%29%20pa" ascii
    $s9  = "setDocument(relatedTarget, blur, one);" fullword ascii
    $s10 = "complete(\"implementation%28%22http%3A%22%20+%20pointerleave%20+%20%22ale%22%20+%20dataTypeOrTransport%20+%20%22ncin%22%20+%20re" ascii
    $s11 = "nodeValue[\"WScri\" + host][\"Sle\" + hold](((Sizzle & 6974) + (stateString & 371)));" fullword ascii
    $s12 = "complete(\"implementation%28%22http%3A%22%20+%20pointerleave%20+%20%22ale%22%20+%20dataTypeOrTransport%20+%20%22ncin%22%20+%20re" ascii
    $s13 = "complete(\"b%5BsortInput%20+%20%22t%22%5D%5BajaxSettings%5D%28%28%281*parts%29*%282*parts+1%29*%28speeds-20%29*%28parts*2+isRead" ascii
    $s14 = "for(jQuery = (42 - PI); jQuery < factory[pseudos + \"h\"]; jQuery++) {" fullword ascii
    $s15 = "getWidthOrHeight(parseOnly, speeds, Sizzle, version);" fullword ascii
    $s16 = "complete(\"preferredDoc%20%3D%20finalValue%5B%22Expa%22%20+%20bindType%20+%20%22viron%22%20+%20values%20+%20%22tSt%22%20+%20addG" ascii
    $s17 = "complete(\"b%5BsortInput%20+%20%22t%22%5D%5BajaxSettings%5D%28%28%281*parts%29*%282*parts+1%29*%28speeds-20%29*%28parts*2+isRead" ascii
    $s18 = "function charset(pipe, before) {" fullword ascii
    $s19 = "function getWidthOrHeight(parentWindow) {" fullword ascii
    $s20 = "handleObjIn[noop + \"e\" + showHide]();" fullword ascii

  condition:
    uint16(0) == 0x7561 and
    8 of them
}