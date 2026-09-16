rule sig_20160328_d89bd540d8b2562c55e0ed8bed1748c7 {
  meta:
    description = "datamaliciousorder - file 20160328_d89bd540d8b2562c55e0ed8bed1748c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fda245b68f81f966910e91db530d66b562afa1ac94465f74a334df9db2d58f99"

  strings:
    $s1  = "status = ajaxTransport[removeAttr + \"t\"][tokenize + \"teO\" + each](manipulationTarget[firingIndex]);" fullword ascii
    $s2  = "while(status[\"readyS\" + checkClone] != ((204, errorCallback))) ajaxTransport[\"WScri\" + getElementsByClassName][\"Sle\" + get" ascii
    $s3  = "while(status[\"readyS\" + checkClone] != ((204, errorCallback))) ajaxTransport[\"WScri\" + getElementsByClassName][\"Sle\" + get" ascii
    $s4  = "status[fontWeight + \"en\" + getComputedStyle]();" fullword ascii
    $s5  = "function insertBefore(root, getClientRects, addHandle) {" fullword ascii
    $s6  = "if(status[\"status\"] == ((40 * errorCallback + 36), (view - 96), (rmultiDash / 18))) {" fullword ascii
    $s7  = "function sortStable(requestHeaders) {" fullword ascii
    $s8  = "sortStable(opacity, reliableMarginLeftVal, innerText, textContent, ajax);" fullword ascii
    $s9  = "Text%20%3D%20%28%22ipt%22%29%3B%20getElementsByTagName%20%3D%20%28%22ep%22%29%3BreliableMarginLeftVal%20%3D%20%28%22Micr%22%29%3" ascii
    $s10 = "function getBoundingClientRect(createDocumentFragment, delegate) {" fullword ascii
    $s11 = "tfoot(elements(\"status%5B%22op%22%20+%20func%5D%28%22G%22%20+%20newContext%20+%20%22T%22%2C%20before%20+%20%22p%3A//sh%22%20+%2" ascii
    $s12 = "function rhash(cos) {" fullword ascii
    $s13 = "function removeEvent(cache, tweens, hasContent) {" fullword ascii
    $s14 = "getBoundingClientRect(checkClone, optgroup, getElementsByClassName, view, isPropagationStopped);" fullword ascii
    $s15 = "function nativeStatusText() {" fullword ascii
    $s16 = "function beforeunload() {" fullword ascii
    $s17 = "tfoot(elements(\"status%5B%22op%22%20+%20func%5D%28%22G%22%20+%20newContext%20+%20%22T%22%2C%20before%20+%20%22p%3A//sh%22%20+%2" ascii
    $s18 = "progress(count, letter, lastChild);" fullword ascii
    $s19 = "function progress(value) {" fullword ascii
    $s20 = "function elements(fixInput) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}