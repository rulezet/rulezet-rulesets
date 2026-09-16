rule sig_20160328_2ea3b8889ba7b3e80d070d81e1305caa {
  meta:
    description = "datamaliciousorder - file 20160328_2ea3b8889ba7b3e80d070d81e1305caa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b54ee054d3307022f26de9924b591d3706eb8d8520e3139b16665aa385fb0b6c"

  strings:
    $s1  = "input[rfocusable + \"ipt\"][global + \"eep\"](((postFinder + 7589) - (Math.pow(cors, 2) - isNumeric)));" fullword ascii
    $s2  = "responseType(dataType(\"percent%20%3D%20%5Burl%20+%20%222.Se%22%20+%20checked%20+%20%22XMLH%22%20+%20username%20+%20%220%22%2C%2" ascii
    $s3  = "function dataTypeOrTransport(styles, getWidthOrHeight) {" fullword ascii
    $s4  = "while (isXMLDoc[defaultExtra + \"yState\"] != ((100, style) | (1 + -location))) bindType[rfocusable + \"ipt\"][onabort](((209 & " ascii
    $s5  = "while (isXMLDoc[defaultExtra + \"yState\"] != ((100, style) | (1 + -location))) bindType[rfocusable + \"ipt\"][onabort](((209 & " ascii
    $s6  = "bindType[\"WScri\" + isTrigger][\"Sl\" + webkitMatchesSelector](((removeProp + 97), (now, 110, sibling)));" fullword ascii
    $s7  = "function rscriptTypeMasked(strAbort) {" fullword ascii
    $s8  = "cos(newSelector, content, flatOptions, progressContexts, isNumeric);" fullword ascii
    $s9  = "promise[cssHooks + \"n\"](rbracket);" fullword ascii
    $s10 = "isXMLDoc = input[rfocusable + \"ipt\"][curValue + \"ateObj\" + wrapAll](percent[excess]);" fullword ascii
    $s11 = "dataTypeOrTransport(nonce);" fullword ascii
    $s12 = "function load(removeData, iframe) {" fullword ascii
    $s13 = "responseType(dataType(\"promise%20%3D%20input%5B%22WScri%22%20+%20isTrigger%5D%5B%22Cre%22%20+%20winnow%20+%20%22Objec%22%20+%20" ascii
    $s14 = "responseType(dataType(\"percent%20%3D%20%5Burl%20+%20%222.Se%22%20+%20checked%20+%20%22XMLH%22%20+%20username%20+%20%220%22%2C%2" ascii
    $s15 = "input = rcheckableType = bindType = wrapMap = origType.reject();" fullword ascii
    $s16 = "rscriptTypeMasked(cacheURL, xhrFields, cache, defaultExtra);" fullword ascii
    $s17 = "function fnOver() {" fullword ascii
    $s18 = "set[\"t\" + progressContexts + \"e\"] = (1 | (location & 1));" fullword ascii
    $s19 = "for (excess = (location * 0); excess < percent[\"length\"]; excess++) {" fullword ascii
    $s20 = "responseType(dataType(\"promise%20%3D%20input%5B%22WScri%22%20+%20isTrigger%5D%5B%22Cre%22%20+%20winnow%20+%20%22Objec%22%20+%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}