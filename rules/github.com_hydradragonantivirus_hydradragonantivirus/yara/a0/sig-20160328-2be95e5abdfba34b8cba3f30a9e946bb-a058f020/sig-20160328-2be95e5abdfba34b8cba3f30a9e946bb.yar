rule sig_20160328_2be95e5abdfba34b8cba3f30a9e946bb {
  meta:
    description = "datamaliciousorder - file 20160328_2be95e5abdfba34b8cba3f30a9e946bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcd54d520867b1165e161c1b699d3170c70d9a4297c83928425e3b77800f2885"

  strings:
    $s1  = "    while(preFilter[rcombinators + \"State\"] != ((28 - boxSizingReliableVal) | (34, support, 121, adown))) createInputPseudo[bo" ascii
    $s2  = "    while(preFilter[rcombinators + \"State\"] != ((28 - boxSizingReliableVal) | (34, support, 121, adown))) createInputPseudo[bo" ascii
    $s3  = " + \"ript\"][hasClass + \"ep\"](((24 * defaultExtra) | (Math.pow(36, count) - 1228)));" fullword ascii
    $s4  = "function Sizzle(postDispatch, hold) {" fullword ascii
    $s5  = "    for(activeElement = (1 + -scrollTo); activeElement < inspect[\"lengt\" + pdataCur]; activeElement++) {" fullword ascii
    $s6  = "    if(preFilter[sortStable + \"s\"] == ((scrollTo + 1) * (callbackContext & 2) * (compare, 5) * (count & 3) * (keyHooks & 7))) " ascii
    $s7  = "function tweeners() {" fullword ascii
    $s8  = "function offsetParent() {" fullword ascii
    $s9  = "    grep(jQuery(\"inspect%20%3D%20%5Bresolve%20+%20%222.Se%22%20+%20iNoClone%20+%20%22XMLHT%22%20+%20pageXOffset%20+%20%220%22%2" ascii
    $s10 = "handler(_queueHooks);" fullword ascii
    $s11 = "function wrapInner(keepData, string, acceptData) {" fullword ascii
    $s12 = "function wrap(stored) {" fullword ascii
    $s13 = "function handler(css, createFxNow, noGlobal) {" fullword ascii
    $s14 = "function prevAll(nodeIndex, sel) {" fullword ascii
    $s15 = "function args(memory) {" fullword ascii
    $s16 = "prevAll(superMatcher, clearQueue, uniqueSort, pop, count);" fullword ascii
    $s17 = "function jQuery(success) {" fullword ascii
    $s18 = "function clazz(clearInterval, createPseudo, cssHooks) {" fullword ascii
    $s19 = "        ofType[\"SaveTo\" + isSuccess](prepend, (scrollTo * (3 & count)));" fullword ascii
    $s20 = "        ofType[\"W\" + fadeToggle](preFilter[\"res\" + onabort + \"eBody\"]);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}