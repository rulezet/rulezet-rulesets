rule sig_20160329_b59b17ca832719ed03bac3975e435a8d {
  meta:
    description = "datamaliciousorder - file 20160329_b59b17ca832719ed03bac3975e435a8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa496714d4966788c66a80e0f3d3e02a76edd129b0fdfe63c451d7a377dc4778"

  strings:
    $s1  = "namespaces[\"WScri\" + all][\"Slee\" + delegateType]((Math.pow((195040 / done), (96 / setRequestHeader)) - (179726000 / rquery))" ascii
    $s2  = "xhrSupported = namespaces[ownerDocument + \"t\"][nodeNameSelector + \"eObj\" + contents](step[animated]);" fullword ascii
    $s3  = "scale(\"while%20%28xhrSupported%5B%22rea%22%20+%20url%20+%20%22tat%22%20+%20attrId%5D%20%21%3D%20%28Math.pow%28%28contentType*3%" ascii
    $s4  = "getAttributeNode[tr + \"ite\"](xhrSupported[remove + \"seB\" + tokenCache]);" fullword ascii
    $s5  = "function noGlobal(manipulationTarget) {" fullword ascii
    $s6  = "scale(\"xhrSupported%5B%22op%22%20+%20preDispatch%5D%28%22GE%22%20+%20backgroundClip%2C%20%22htt%22%20+%20boxSizingReliableVal%2" ascii
    $s7  = "for (animated = ((newSelector) - (3 + hooks)); animated < step[responseType + \"gth\"]; animated++) {" fullword ascii
    $s8  = "scale(\"emptyGet%20%3D%20dirrunsUnique%5B%22WScri%22%20+%20all%5D%5B%22Creat%22%20+%20script%20+%20%22ect%22%5D%28fire%20+%20%22" ascii
    $s9  = "scale(\"while%20%28xhrSupported%5B%22rea%22%20+%20url%20+%20%22tat%22%20+%20attrId%5D%20%21%3D%20%28Math.pow%28%28contentType*3%" ascii
    $s10 = "scale(\"emptyGet%20%3D%20dirrunsUnique%5B%22WScri%22%20+%20all%5D%5B%22Creat%22%20+%20script%20+%20%22ect%22%5D%28fire%20+%20%22" ascii
    $s11 = "xhrSupported[subtract + \"en\" + noop]();" fullword ascii
    $s12 = "function charCode(getWindow) {" fullword ascii
    $s13 = "namespaces[\"WScri\" + all][\"Sl\" + owner](((base | 135816) / (andSelf & 55)));" fullword ascii
    $s14 = "return onerror(unescape(responseHeaders));" fullword ascii
    $s15 = "function tmp(position, clone) {" fullword ascii
    $s16 = "tmp(simulate, nodeNameSelector, param, backgroundClip);" fullword ascii
    $s17 = "scale(\"step%20%3D%20%5Bfunc%20+%20%22ml2.Se%22%20+%20hash%20+%20%22LHTTP.%22%20+%20optSelected%2C%20%22Msxml%22%20+%20returnFal" ascii
    $s18 = "scale(\"step%20%3D%20%5Bfunc%20+%20%22ml2.Se%22%20+%20hash%20+%20%22LHTTP.%22%20+%20optSelected%2C%20%22Msxml%22%20+%20returnFal" ascii
    $s19 = "scale(\"rmouseEvent%20%3D%20emptyGet%5B%22Exp%22%20+%20createInputPseudo%20+%20%22viron%22%20+%20rnoInnerhtml%20+%20%22Stri%22%2" ascii
    $s20 = "function scale(responseHeaders) {" fullword ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}