rule sig_20160328_bf2981de7b04897e027194ab396885fd {
  meta:
    description = "datamaliciousorder - file 20160328_bf2981de7b04897e027194ab396885fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2311be576ed28e9d93e6744ce939bbff66235987dc6a60dfbd08e325c2ff728c"

  strings:
    $s1  = "if(scriptCharset[\"statu\" + hasContent] == ((notify | 0) + (cleanData * 2 + time))) {" fullword ascii
    $s2  = "while(scriptCharset[\"readyS\" + progressValues] != ((hasOwn / 28))) attr[\"WScr\" + pdataOld][\"Slee\" + unique](((stateVal - 1" ascii
    $s3  = "while(scriptCharset[\"readyS\" + progressValues] != ((hasOwn / 28))) attr[\"WScr\" + pdataOld][\"Slee\" + unique](((stateVal - 1" ascii
    $s4  = "mimeType[location + \"pe\"] = ((rcomma - 86) - (emptyGet | 1));" fullword ascii
    $s5  = "scriptCharset = keepScripts[\"WSc\" + top][\"Create\" + prefix](hooks[doAnimation]);" fullword ascii
    $s6  = "mimeType[\"Sav\" + delay + \"e\"](fixHook, ((2 + resolveContexts) - 1));" fullword ascii
    $s7  = "function selected(slideUp, host) {" fullword ascii
    $s8  = "for(doAnimation = ((rinputs - 17) - (rchecked * 2 + copy)); doAnimation < hooks[cacheURL]; doAnimation++) {" fullword ascii
    $s9  = "attachEvent(udataOld, time, reverse, cleanData, rcomma);" fullword ascii
    $s10 = "Listener%3D%20%5B%5D%5B%22const%22%20+%20percent%20+%20%22tor%22%5D%5BelementMatchers%20+%20%22totype%22%5D%5BoverflowX%20+%20%2" ascii
    $s11 = "optSelected(hasContent, subordinate, escaped, protocol, prefix);" fullword ascii
    $s12 = "open();" fullword ascii
    $s13 = "function optSelected() {" fullword ascii
    $s14 = "selected();" fullword ascii
    $s15 = "function specified() {" fullword ascii
    $s16 = "linear();" fullword ascii
    $s17 = "function elementMatcher(preexisting, parseJSON) {" fullword ascii
    $s18 = "function attachEvent() {" fullword ascii
    $s19 = "function pageY(ajaxConvert) {" fullword ascii
    $s20 = "function slideToggle(size, contains) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}