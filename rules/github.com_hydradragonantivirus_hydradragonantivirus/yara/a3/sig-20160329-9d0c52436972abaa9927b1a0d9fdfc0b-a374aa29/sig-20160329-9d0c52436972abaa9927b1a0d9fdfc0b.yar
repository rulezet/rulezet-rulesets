rule sig_20160329_9d0c52436972abaa9927b1a0d9fdfc0b {
  meta:
    description = "datamaliciousorder - file 20160329_9d0c52436972abaa9927b1a0d9fdfc0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "517ac77aacd9e425a1b695fa3fccf84aae92f2f2acceffe3875e05079c456e84"

  strings:
    $s1  = "documentIsHTML[postMap + \"od\" + byElement] = ((120 / bind));" fullword ascii
    $s2  = "function pipe(getPropertyValue, initialInUnit, _data) {" fullword ascii
    $s3  = "camelCase(bind, on, byElement, rcleanScript, postMap);" fullword ascii
    $s4  = "if(postFilter[attrNames + \"s\"] == ((1 + which) * (221 & parent))) {" fullword ascii
    $s5  = "doneName(rcleanScript, _removeData, defineProperty, ajaxTransport, dispatch);" fullword ascii
    $s6  = "documentIsHTML[rheaders + \"ToFi\" + ap](udataOld, (2 + (which & 0)));" fullword ascii
    $s7  = "rscriptTypeMasked(hasData, values, complete);" fullword ascii
    $s8  = "postFilter = protocol[progressValues + \"ript\"][rprotocol + \"eObje\" + showHide](resolveContexts[init]);" fullword ascii
    $s9  = "etag(\"protocol%5BquerySelectorAll%20+%20%22ipt%22%5D%5BrequestHeaders%20+%20%22p%22%5D%28%28%281+checkDisplay%29*13+%28Math.pow" ascii
    $s10 = "etag(\"while%20%28postFilter%5B%22ready%22%20+%20offset%20+%20%22te%22%5D%20%21%3D%20%28%28createHTMLDocument+2%29%29%29%20file%" ascii
    $s11 = "etag(\"while%20%28postFilter%5B%22ready%22%20+%20offset%20+%20%22te%22%5D%20%21%3D%20%28%28createHTMLDocument+2%29%29%29%20file%" ascii
    $s12 = "etag(\"protocol%5BquerySelectorAll%20+%20%22ipt%22%5D%5BrequestHeaders%20+%20%22p%22%5D%28%28%281+checkDisplay%29*13+%28Math.pow" ascii
    $s13 = "for(init = ((winnow / 8) - (checkContext - 20)); init < resolveContexts[result + \"ength\"]; init++) {" fullword ascii
    $s14 = "pipe(nodeIndex);" fullword ascii
    $s15 = "function rscriptTypeMasked(firstDataType, vendorPropName, beforeSend) {" fullword ascii
    $s16 = "parseOnly[invert + \"un\"](udataOld);" fullword ascii
    $s17 = "fontWeight(special, ajaxTransport, remaining, event);" fullword ascii
    $s18 = "function addClass(elemData, setRequestHeader, innerHTML) {" fullword ascii
    $s19 = "function newContext() {" fullword ascii
    $s20 = "function overflowX() {" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}