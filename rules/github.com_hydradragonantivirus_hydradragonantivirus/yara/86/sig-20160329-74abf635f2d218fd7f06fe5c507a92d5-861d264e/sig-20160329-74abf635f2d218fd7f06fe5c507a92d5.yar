rule sig_20160329_74abf635f2d218fd7f06fe5c507a92d5 {
  meta:
    description = "datamaliciousorder - file 20160329_74abf635f2d218fd7f06fe5c507a92d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49ebd23224f5aac8bb1b5b0adeb0aef883119e1b35733152e2e9a6dedc721e0d"

  strings:
    $s1  = "handleObj(\"source%20%3D%20%5B%22Msxm%22%20+%20size%20+%20%22Serve%22%20+%20requestHeadersNames%20+%20%22LHT%22%20+%20rnative%20" ascii
    $s2  = "matcherFromTokens[submit](compiled[\"res\" + matchIndexes + \"Body\"]);" fullword ascii
    $s3  = "handleObj(\"preFilter%20%3D%20conditionFn%5B%22Exp%22%20+%20filter%20+%20%22Envir%22%20+%20contexts%20+%20%22tSt%22%20+%20getCom" ascii
    $s4  = "handleObj(\"preFilter%20%3D%20conditionFn%5B%22Exp%22%20+%20filter%20+%20%22Envir%22%20+%20contexts%20+%20%22tSt%22%20+%20getCom" ascii
    $s5  = "handleObj(\"while%20%28compiled%5Breject%20+%20%22ySta%22%20+%20protocol%5D%20%21%3D%20%28%28isWindow+2%29+%28getAllResponseHead" ascii
    $s6  = "handleObj(\"while%20%28compiled%5Breject%20+%20%22ySta%22%20+%20protocol%5D%20%21%3D%20%28%28isWindow+2%29+%28getAllResponseHead" ascii
    $s7  = "amd[\"WScr\" + maxIterations][\"Slee\" + boxSizingReliable](((appendTo - 877) & (find | 5964)));" fullword ascii
    $s8  = "matcherFromTokens[propFilter + \"eToFi\" + toggle](preFilter, ((rdashAlpha + 2) & (isWindow | 2)));" fullword ascii
    $s9  = "handleObj(\"source%20%3D%20%5B%22Msxm%22%20+%20size%20+%20%22Serve%22%20+%20requestHeadersNames%20+%20%22LHT%22%20+%20rnative%20" ascii
    $s10 = "function win(hasContent) {" fullword ascii
    $s11 = "for(load = ((rdashAlpha & 0) / (contextBackup, 111, contextBackup)); load < source[remove + \"th\"]; load++) {" fullword ascii
    $s12 = "conditionFn[\"R\" + pixelMarginRightVal](preFilter);" fullword ascii
    $s13 = "checkOn(hash, progressContexts);" fullword ascii
    $s14 = "function rnamespace(compare, valHooks) {" fullword ascii
    $s15 = "function escaped(forward, node) {" fullword ascii
    $s16 = "function maxWidth() {" fullword ascii
    $s17 = "function timers() {" fullword ascii
    $s18 = "maxWidth(checkbox, extra);" fullword ascii
    $s19 = "function chainable(createOptions, addHandle) {" fullword ascii
    $s20 = "function isArray() {" fullword ascii

  condition:
    uint16(0) == 0x7372 and
    8 of them
}