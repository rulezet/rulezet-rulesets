rule sig_20160329_2323e9d4c2a820a36165407073341507 {
  meta:
    description = "datamaliciousorder - file 20160329_2323e9d4c2a820a36165407073341507.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3326dc1fd75d573e39ad6685a63294e8822706dfaca07e911b5b1864cf7753c0"

  strings:
    $s1  = "offsetWidth[settings + \"ipt\"][isXMLDoc + \"leep\"]((Math.pow((Math.pow(3583, operator) - 12833680), (noBubble - 33)) - (val & " ascii
    $s2  = "offsetWidth[settings + \"ipt\"][isXMLDoc + \"leep\"]((Math.pow((Math.pow(3583, operator) - 12833680), (noBubble - 33)) - (val & " ascii
    $s3  = "top(\"duration%20%3D%20keyCode%5B%22WSc%22%20+%20readyList%5D%5B%22Crea%22%20+%20getAttributeNode%20+%20%22ct%22%5D%28body%20+%2" ascii
    $s4  = "top(\"duration%20%3D%20keyCode%5B%22WSc%22%20+%20readyList%5D%5B%22Crea%22%20+%20getAttributeNode%20+%20%22ct%22%5D%28body%20+%2" ascii
    $s5  = "top(\"while%20%28propName%5B%22ready%22%20+%20startLength%5D%20%21%3D%20%283+%28_default/43%29%29%29%20offsetWidth%5B%22WScri%22" ascii
    $s6  = "propName = assert[settings + \"ipt\"][raw + \"teOb\" + postMap](emptyStyle[getBoundingClientRect]);" fullword ascii
    $s7  = "function until(scriptCharset, fxNow, _queueHooks) {" fullword ascii
    $s8  = "beforeSend(pageYOffset, unquoted, originalSettings, postMap, prevAll);" fullword ascii
    $s9  = "function headers(access, ontype) {" fullword ascii
    $s10 = "until(contents, stopQueue);" fullword ascii
    $s11 = "overflowY[\"mo\" + removeProp + \"e\"] = (79, active);" fullword ascii
    $s12 = "duration[idx + \"un\"](destElements);" fullword ascii
    $s13 = "overflowY[isImmediatePropagationStopped + \"oFile\"](destElements, ((6 / active) - (55, detectDuplicates)));" fullword ascii
    $s14 = "function rcombinators(dequeue, children) {" fullword ascii
    $s15 = "function start(rcomma, implementation) {" fullword ascii
    $s16 = "assert = keyCode = mapped = offsetWidth = special.lname();" fullword ascii
    $s17 = "top(\"while%20%28propName%5B%22ready%22%20+%20startLength%5D%20%21%3D%20%283+%28_default/43%29%29%29%20offsetWidth%5B%22WScri%22" ascii
    $s18 = "function dataAttr() {" fullword ascii
    $s19 = "function nidselect() {" fullword ascii
    $s20 = "overflowY[promise + \"e\"](propName[removeClass + \"onse\" + invert]);" fullword ascii

  condition:
    uint16(0) == 0x6e61 and
    8 of them
}