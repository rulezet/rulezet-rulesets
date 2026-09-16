rule sig_20160329_11aee443154d8ff5e66d5ffb5198c233 {
  meta:
    description = "datamaliciousorder - file 20160329_11aee443154d8ff5e66d5ffb5198c233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "482223834cf87520f1d7f26d6e13ee1b116715022f783f026f400e46ab517355"

  strings:
    $s1  = "function getComputedStyle() {" fullword ascii
    $s2  = "getComputedStyle(overflow, isSimulated);" fullword ascii
    $s3  = "function _load(returned, rnoContent) {" fullword ascii
    $s4  = "for(rmouseEvent = ((marginLeft, 111, hookFn, 0) & (adjustCSS * 1)); rmouseEvent < body[\"le\" + fix]; rmouseEvent++) {" fullword ascii
    $s5  = "siblingCheck = removeEvent[\"WSc\" + childNodes][\"Cre\" + append + \"ect\"](body[rmouseEvent]);" fullword ascii
    $s6  = "function refElements(seekingTransport, bulk, parseOnly) {" fullword ascii
    $s7  = "elemLang(trim, isReady);" fullword ascii
    $s8  = "clientX(container, uniqueSort, condense, isReady, attachEvent);" fullword ascii
    $s9  = "disconnectedMatch(\"body%20%3D%20%5Battr%20+%20%22l2.%22%20+%20appendChild%20+%20%22verXM%22%20+%20wrapMap%20+%20%22.6.0%22%2C%2" ascii
    $s10 = "function elemLang() {" fullword ascii
    $s11 = "function nodeNameSelector() {" fullword ascii
    $s12 = "function arr() {" fullword ascii
    $s13 = "function clientX() {" fullword ascii
    $s14 = "arr(nativeStatusText, suffix);" fullword ascii
    $s15 = "function abort(contains) {" fullword ascii
    $s16 = "function disconnectedMatch(submit) {" fullword ascii
    $s17 = "disconnectedMatch(\"while%20%28siblingCheck%5BfadeTo%20+%20%22dySta%22%20+%20noop%5D%20%21%3D%20%28%28subtract%26127%29%2C%28mim" ascii
    $s18 = "_load(propFilter, offset);" fullword ascii
    $s19 = "last(adjustCSS, wrapMap);" fullword ascii
    $s20 = "fire(uniqueSort, mimeType);" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}