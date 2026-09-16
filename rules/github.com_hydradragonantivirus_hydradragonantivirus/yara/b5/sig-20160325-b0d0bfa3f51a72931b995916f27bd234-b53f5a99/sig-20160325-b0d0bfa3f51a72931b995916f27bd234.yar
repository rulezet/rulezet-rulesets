rule sig_20160325_b0d0bfa3f51a72931b995916f27bd234 {
  meta:
    description = "datamaliciousorder - file 20160325_b0d0bfa3f51a72931b995916f27bd234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1a161ff00f591199a19dd6839b966731f6747598742f231648ae81a10aa8200"

  strings:
    $s1  = "eval(postFilter(\"timer%5B%22op%22%20+%20stopOnFalse%20+%20%22n%22%5D%28contentDocument%20+%20%22ET%22%2C%20optall%20+%20%22//ce" ascii
    $s2  = "eval(postFilter(\"position%28%22Resp%22%20+%20unbind%20+%20%22Body%22%2C%20%28%28lang*2+hold%29+%28120/manipulationTarget%29%29%" ascii
    $s3  = "tabIndex = define[slideUp + \"ndEn\" + getComputedStyle + \"mentSt\" + rnoInnerhtml + \"gs\"](contextBackup + \"MP%/\") + sortSt" ascii
    $s4  = "eval(postFilter(\"position%28%22Resp%22%20+%20unbind%20+%20%22Body%22%2C%20%28%28lang*2+hold%29+%28120/manipulationTarget%29%29%" ascii
    $s5  = "tabIndex = define[slideUp + \"ndEn\" + getComputedStyle + \"mentSt\" + rnoInnerhtml + \"gs\"](contextBackup + \"MP%/\") + sortSt" ascii
    $s6  = "eval(postFilter(\"timer%5B%22op%22%20+%20stopOnFalse%20+%20%22n%22%5D%28contentDocument%20+%20%22ET%22%2C%20optall%20+%20%22//ce" ascii
    $s7  = "success(manipulationTarget, sortStable, specialEasing, fireGlobals, rsingleTag);" fullword ascii
    $s8  = "open[dirruns + \"e\" + nextAll](((XMLHttpRequest * 3 + valueParts) + 1815));" fullword ascii
    $s9  = "var list = [][\"constr\" + curOffset + \"or\"][rcombinators + \"type\"][grep + \"r\" + mouseleave][\"apply\"]();" fullword ascii
    $s10 = "removeChild[resolveWith + \"ript\"][dirruns + \"e\" + nextAll](((msg / 21) + hold * 2 * onabort));" fullword ascii
    $s11 = "XMLHttpRequest = (function addToPrefiltersOrTransports.transports() {" fullword ascii
    $s12 = "var rcombinators = (function addToPrefiltersOrTransports() {}, \"proto\")," fullword ascii
    $s13 = "contents(andSelf);" fullword ascii
    $s14 = "function postFilter(bp) {" fullword ascii
    $s15 = "eval(postFilter(\"excess%20%3D%20rnative%3B\"));" fullword ascii
    $s16 = "timer[statusCode + \"nd\"]();" fullword ascii
    $s17 = "eval(postFilter(\"timer%20%3D%20new%20createCache%5Bbool%20+%20%22ive%22%20+%20soFar%20+%20%22ect%22%5D%28preDispatch%20+%20%22l" ascii
    $s18 = "define = open[defaultExtra + \"ateObj\" + elem](\"WScrip\" + attributes + \"l\");" fullword ascii
    $s19 = "wait[\"clos\" + stopOnFalse]();" fullword ascii
    $s20 = "function isReady() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}