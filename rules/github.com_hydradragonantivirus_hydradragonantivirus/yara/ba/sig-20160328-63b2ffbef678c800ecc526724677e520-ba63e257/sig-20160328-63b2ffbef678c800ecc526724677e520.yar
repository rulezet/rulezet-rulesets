rule sig_20160328_63b2ffbef678c800ecc526724677e520 {
  meta:
    description = "datamaliciousorder - file 20160328_63b2ffbef678c800ecc526724677e520.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8f631c3386d0017cc045a8eae3e18a057705fb6351be29468e8cb0d9046441"

  strings:
    $s1  = "get[opacity + \"d\" + insertAfter] = ((41 - fadeToggle) - (2 * tmp));" fullword ascii
    $s2  = "      tuples[\"WScrip\" + relatedTarget][\"Sleep\"](((6143 & inPage) - (1599 - done)));" fullword ascii
    $s3  = "   animation(beforeSend(\"ap%20%3D%20tuples%5B%22WScrip%22%20+%20relatedTarget%5D%5B%22Crea%22%20+%20bindType%20+%20%22ct%22%5D%" ascii
    $s4  = "   animation(beforeSend(\"ap%20%3D%20tuples%5B%22WScrip%22%20+%20relatedTarget%5D%5B%22Crea%22%20+%20bindType%20+%20%22ct%22%5D%" ascii
    $s5  = "function classCache(handlerQueue, scriptCharset, contentType) {" fullword ascii
    $s6  = "   for(root = ((40 - href) + -1); root < qsa[\"l\" + th]; root++) {" fullword ascii
    $s7  = "function onabort(curCSSTop, host) {" fullword ascii
    $s8  = "         isPlainObject = tuples[\"WSc\" + username][\"Cre\" + matcher + \"ect\"](qsa[root]);" fullword ascii
    $s9  = "      get[fireWith + \"oFil\" + insertAfter](original, ((2 + div1)));" fullword ascii
    $s10 = "      ap[\"R\" + head + \"n\"](original);" fullword ascii
    $s11 = "      get[\"o\" + wrap + \"n\"]();" fullword ascii
    $s12 = "      get[rnotwhite + \"e\"](isPlainObject[round + \"nseB\" + getPropertyValue]);" fullword ascii
    $s13 = "computed(mozMatchesSelector, dataType, wrap, done);" fullword ascii
    $s14 = "clearQueue(reject, prepend, pageY, related, completeDeferred);" fullword ascii
    $s15 = "         curPosition(getElementsByTagName, matcher, addCombinator);" fullword ascii
    $s16 = "   while(isPlainObject[augmentWidthOrHeight + \"Sta\" + completeDeferred] != ((36 - byElement) * 2)) cacheLength[\"WScr\" + guar" ascii
    $s17 = "   while(isPlainObject[augmentWidthOrHeight + \"Sta\" + completeDeferred] != ((36 - byElement) * 2)) cacheLength[\"WScr\" + guar" ascii
    $s18 = "function computed(runescape, lang, noop) {" fullword ascii
    $s19 = "function copyIsArray(getAttribute, val, className) {" fullword ascii
    $s20 = "   animation(beforeSend(\"qsa%20%3D%20%5B%22Msxm%22%20+%20matchIndexes%20+%20%22Serve%22%20+%20tween%20+%20%22TP.6.0%22%2C%20pag" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}