rule sig_20160329_b1bd400d3556f8531a5c85bf3eb11540 {
  meta:
    description = "datamaliciousorder - file 20160329_b1bd400d3556f8531a5c85bf3eb11540.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6054cfb11826299ca3a02996e3a08a69187d7b30781ff4f3cbd2dc28ceda02"

  strings:
    $s1  = "parseXML(rquickExpr, tmp, getAllResponseHeaders, structure, mapped);" fullword ascii
    $s2  = "function flatOptions(dataAndEvents, rscriptTypeMasked) {" fullword ascii
    $s3  = "function run(defaultPrefilter, getElementsByClassName, body) {" fullword ascii
    $s4  = "_jQuery(\"while%20%28matchContext%5B_load%20+%20%22dyS%22%20+%20parseJSON%5D%20%21%3D%20%28%28arr%29%7C%282*hasDuplicate%29%29%2" ascii
    $s5  = "function addToPrefiltersOrTransports(responseHeaders, class2type) {" fullword ascii
    $s6  = "rfxtypes[\"Wri\" + url](matchContext[\"resp\" + Data + \"ody\"]);" fullword ascii
    $s7  = "run(padding, _load);" fullword ascii
    $s8  = "curLeft(isReady, rquickExpr, self, colgroup);" fullword ascii
    $s9  = "flatOptions(requestHeaders, settings, cacheLength, structure);" fullword ascii
    $s10 = "function node() {" fullword ascii
    $s11 = "function _jQuery(parseOnly) {" fullword ascii
    $s12 = "function crossDomain(cssExpand, visibility) {" fullword ascii
    $s13 = "function done(cssNumber, whitespace) {" fullword ascii
    $s14 = "_jQuery(\"response%5Bpadding%20+%20%22ipt%22%5D%5BresponseText%20+%20%22ep%22%5D%28%28%28initialInUnit-4305%29%7C%28removeEvent*" ascii
    $s15 = "function curLeft(eventPath) {" fullword ascii
    $s16 = "done(settings, collection, obj, initialInUnit, active);" fullword ascii
    $s17 = "node(ap, rcssNum, _load);" fullword ascii
    $s18 = "function parseXML(context) {" fullword ascii
    $s19 = "linear = 554;" fullword ascii
    $s20 = "input%29%3B\");" fullword ascii

  condition:
    uint16(0) == 0x696c and
    8 of them
}