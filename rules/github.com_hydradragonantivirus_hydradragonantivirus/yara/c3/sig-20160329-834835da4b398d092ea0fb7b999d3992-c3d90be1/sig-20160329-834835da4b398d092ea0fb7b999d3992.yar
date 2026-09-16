rule sig_20160329_834835da4b398d092ea0fb7b999d3992 {
  meta:
    description = "datamaliciousorder - file 20160329_834835da4b398d092ea0fb7b999d3992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "821328c3e508a945dc799a6fba026ddfc045a916d9eabcb83cc33bd8adc5d7be"

  strings:
    $s1  = "if(holdReady[\"s\" + wrapAll + \"s\"] == (Math.pow((Math.pow(100, setMatchers) - 9892), (pushStack - 32)) - (tween | 3208))) {" fullword ascii
    $s2  = "for(then = ((activeElement, 72, step) - (156, wrapInner, 13)); then < curCSSLeft[getBoundingClientRect]; then++) {" fullword ascii
    $s3  = "requestHeaders(\"while%20%28holdReady%5BdataTypeExpression%20+%20%22tate%22%5D%20%21%3D%20%28prev+1%29%29%20acceptData%5Brpseudo" ascii
    $s4  = "requestHeaders(\"while%20%28holdReady%5BdataTypeExpression%20+%20%22tate%22%5D%20%21%3D%20%28prev+1%29%29%20acceptData%5Brpseudo" ascii
    $s5  = "Data[bind + \"un\"](rfxtypes);" fullword ascii
    $s6  = "holdReady = idx[\"WSc\" + one][\"Crea\" + flag + \"ect\"](curCSSLeft[then]);" fullword ascii
    $s7  = "return relatedTarget(unescape(newCache));" fullword ascii
    $s8  = "requestHeaders(\"Data%20%3D%20firstChild%5B%22WScrip%22%20+%20responseHeaders%5D%5B%22Create%22%20+%20count%20+%20%22ect%22%5D%2" ascii
    $s9  = "function getWidthOrHeight(deepDataAndEvents, pdataOld) {" fullword ascii
    $s10 = "requestHeaders(\"Data%20%3D%20firstChild%5B%22WScrip%22%20+%20responseHeaders%5D%5B%22Create%22%20+%20count%20+%20%22ect%22%5D%2" ascii
    $s11 = "fire(contains, onerror, activeElement, promise, _data);" fullword ascii
    $s12 = "function expando(fail, constructor) {" fullword ascii
    $s13 = "function checkOn(readyList, fxNow, rcssNum) {" fullword ascii
    $s14 = "function requestHeaders(newCache) {" fullword ascii
    $s15 = "function defaultDisplay() {" fullword ascii
    $s16 = "function safeActiveElement(visible, matches) {" fullword ascii
    $s17 = "excess(fnOver, dataFilter, stop, bubbleType);" fullword ascii
    $s18 = "function matchExpr(winnow) {" fullword ascii
    $s19 = "function excess(start, MAX_NEGATIVE, parentWindow) {" fullword ascii
    $s20 = "function div() {" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}