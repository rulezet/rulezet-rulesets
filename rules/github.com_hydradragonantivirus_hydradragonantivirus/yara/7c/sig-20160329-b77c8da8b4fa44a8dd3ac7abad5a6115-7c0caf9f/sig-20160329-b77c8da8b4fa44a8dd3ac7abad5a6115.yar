rule sig_20160329_b77c8da8b4fa44a8dd3ac7abad5a6115 {
  meta:
    description = "datamaliciousorder - file 20160329_b77c8da8b4fa44a8dd3ac7abad5a6115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bceb70524bc368c559aa8caba313960e4020961981f81cd49960f674bb3ccc00"

  strings:
    $s1  = "password = event = check = fadeIn = curPosition.off();" fullword ascii
    $s2  = "matchedCount[rchecked + \"Fil\" + proxy](eventPath, ((53 - rejectWith) & (115, rtagName, 3)));" fullword ascii
    $s3  = "fadeIn[close + \"ript\"][unique + \"ep\"](((Deferred / 2) | (Math.pow(preFilters, 2) - height)));" fullword ascii
    $s4  = "function container(relatedTarget, window, related) {" fullword ascii
    $s5  = "function rscriptTypeMasked(xhrSupported, rsubmittable) {" fullword ascii
    $s6  = "getElementsByName(\"while%20%28qsa%5B%22ready%22%20+%20rnamespace%20+%20%22te%22%5D%20%21%3D%20%28%2840/valueIsBorderBox%29+%289" ascii
    $s7  = "getElementsByName(\"while%20%28qsa%5B%22ready%22%20+%20rnamespace%20+%20%22te%22%5D%20%21%3D%20%28%2840/valueIsBorderBox%29+%289" ascii
    $s8  = "qsa[identifier + \"en\" + grep]();" fullword ascii
    $s9  = "matchedCount[namespace + \"p\" + proxy + \"n\"]();" fullword ascii
    $s10 = "function button(propFix, keepScripts) {" fullword ascii
    $s11 = "function nodeValue(pipe) {" fullword ascii
    $s12 = "function getElementsByName(parseFromString) {" fullword ascii
    $s13 = "handleObjIn(get, display, namespace, rnamespace);" fullword ascii
    $s14 = "qsa = event[clientX + \"ipt\"][uid + \"eObjec\" + m](boxSizingReliableVal[prepend]);" fullword ascii
    $s15 = "sortStable(value, tmp);" fullword ascii
    $s16 = "getElementsByName(\"event%5B%22WScr%22%20+%20addClass%5D%5B%22Sleep%22%5D%28%28%28value+91%29*%28opener/21%29+%28rejectWith*2+re" ascii
    $s17 = "getElementsByName(\"event%5B%22WScr%22%20+%20addClass%5D%5B%22Sleep%22%5D%28%28%28value+91%29*%28opener/21%29+%28rejectWith*2+re" ascii
    $s18 = "function rnoInnerhtml() {" fullword ascii
    $s19 = "function sortStable() {" fullword ascii
    $s20 = "button();" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}