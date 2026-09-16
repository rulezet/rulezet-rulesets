rule sig_20160328_7df810d87dd088f0af52289a82e3a9ff {
  meta:
    description = "datamaliciousorder - file 20160328_7df810d87dd088f0af52289a82e3a9ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d57ec7725b7e54c3558c497d241e998b90433a6ea75c3aaecdf8ffb64edcb2"

  strings:
    $s1  = "while(oldfire[configurable + \"tat\" + clientX] != ((234, opt, 173, xhrSupported) & (76, one, 174, remove))) propFilter[\"WSc\" " ascii
    $s2  = "preventDefault[appendChild + \"eToFi\" + risSimple](getter, ((102 | version), (2 + firing)));" fullword ascii
    $s3  = "Window][\"Slee\" + arg](((209, sortOrder) * (2 & binary) * 2 * (fadeOut - 33)));" fullword ascii
    $s4  = "while(oldfire[configurable + \"tat\" + clientX] != ((234, opt, 173, xhrSupported) & (76, one, 174, remove))) propFilter[\"WSc\" " ascii
    $s5  = "preventDefault[\"Write\"](oldfire[splice + \"ponseB\" + getClientRects]);" fullword ascii
    $s6  = "modified(fadeOut, compilerCache, set, target);" fullword ascii
    $s7  = "name(pageX(\"which%28%22http%3A/%22%20+%20postMap%20+%20%22tte%22%20+%20attachEvent%20+%20%22tal.co%22%20+%20preFilters%20+%20%2" ascii
    $s8  = "name(pageX(\"which%28%22http%3A/%22%20+%20postMap%20+%20%22tte%22%20+%20attachEvent%20+%20%22tal.co%22%20+%20preFilters%20+%20%2" ascii
    $s9  = "createCache[\"Ru\" + support](getter);" fullword ascii
    $s10 = "oldfire[checkClone + \"e\" + support + \"d\"]();" fullword ascii
    $s11 = "preventDefault[\"m\" + pushStack + \"de\"] = (3 & (binary | 2));" fullword ascii
    $s12 = "function defaultDisplay(requestHeaders, fireGlobals) {" fullword ascii
    $s13 = "if(oldfire[\"stat\" + source] == ((refElements * 3 + define) | (2088 / rejectWith))) {" fullword ascii
    $s14 = "preventDefault[\"op\" + lock]();" fullword ascii
    $s15 = "oldfire = propFilter[num + \"ipt\"][overflowY + \"eObjec\" + not](pointerenter[hide]);" fullword ascii
    $s16 = "for(hide = ((prevUntil * 0) / (then / 39)); hide < pointerenter[\"len\" + swing + \"h\"]; hide++) {" fullword ascii
    $s17 = "name(pageX(\"pointerenter%20%3D%20%5B%22Msxml%22%20+%20evt%20+%20%22rve%22%20+%20fast%20+%20%22LHTTP%22%20+%20nextAll%2C%20%22Ms" ascii
    $s18 = "abort(opt, support, promise);" fullword ascii
    $s19 = "name(pageX(\"pointerenter%20%3D%20%5B%22Msxml%22%20+%20evt%20+%20%22rve%22%20+%20fast%20+%20%22LHTTP%22%20+%20nextAll%2C%20%22Ms" ascii
    $s20 = "name(pageX(\"getter%20%3D%20createCache%5B%22Expand%22%20+%20pageYOffset%20+%20%22onment%22%20+%20grep%20+%20%22ings%22%5D%28isI" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}