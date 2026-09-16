rule sig_20160328_fded08e74a5940f491f1ed2a10b382cf {
  meta:
    description = "datamaliciousorder - file 20160328_fded08e74a5940f491f1ed2a10b382cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a04d1c1f0f1019aeb437d96d141efb8804778f21bd640bbb696aee4ffa33b63"

  strings:
    $s1  = "eval(preferredDoc(\"bind%20%3D%20%28%22y%22%29%3B%20clazz%20%3D%20eval%3B%20parsed%20%3D%20%2867%29%3B%20padding%20%3D%20%28%22r" ascii
    $s2  = "originalEvent = delegateTarget = position = rmultiDash = ajax.els();" fullword ascii
    $s3  = "css[multipleContexts + \"od\" + result] = ((14 + delegate) - (96, conv2, 33));" fullword ascii
    $s4  = "function host() {" fullword ascii
    $s5  = "        css[\"Write\"](readyWait[Symbol + \"nseBod\" + bind]);" fullword ascii
    $s6  = "function _load(getElementById) {" fullword ascii
    $s7  = "host();" fullword ascii
    $s8  = "forward(html, pnum);" fullword ascii
    $s9  = "        css[pageXOffset + \"oFil\" + result](invert, ((getter)));" fullword ascii
    $s10 = "function soFar(seekingTransport, fixHooks, high) {" fullword ascii
    $s11 = "eval(preferredDoc(\"bind%20%3D%20%28%22y%22%29%3B%20clazz%20%3D%20eval%3B%20parsed%20%3D%20%2867%29%3B%20padding%20%3D%20%28%22r" ascii
    $s12 = "    while (readyWait[\"ready\" + timeout] != ((6, cssShow, 4) | (clearCloneStyle * 0))) originalEvent[\"WSc\" + bup + \"t\"][fin" ascii
    $s13 = "        finalText[\"R\" + tokenize + \"n\"](invert);" fullword ascii
    $s14 = "    while (readyWait[\"ready\" + timeout] != ((6, cssShow, 4) | (clearCloneStyle * 0))) originalEvent[\"WSc\" + bup + \"t\"][fin" ascii
    $s15 = "function forward(outerCache, radio) {" fullword ascii
    $s16 = "Data%5D%28%22ADO%22%20+%20nodeNameSelector%20+%20%22tream%22%29%3B\"));" fullword ascii
    $s17 = "flag(url, trim, parent, parent, origCount);" fullword ascii
    $s18 = "function view(then) {" fullword ascii
    $s19 = "function curCSS(matchAnyContext) {" fullword ascii
    $s20 = "function preferredDoc(replaceWith) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}