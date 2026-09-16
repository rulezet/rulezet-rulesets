rule sig_20160328_b5dd657023f315091ad8766ef9f6ad15 {
  meta:
    description = "datamaliciousorder - file 20160328_b5dd657023f315091ad8766ef9f6ad15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "507e23772feb995c239dddc4153fcc7f1000dfb7df021092703831b9b68271ae"

  strings:
    $s1  = "eval(conv2(\"percent%20%3D%20%28%22//idea%22%29%2C%20noop%20%3D%20%28%222.Ser%22%29%2C%20marginRight%20%3D%20%28%22cr%22%29%2C%2" ascii
    $s2  = "while(superMatcher[getResponseHeader + \"dySt\" + escapedWhitespace] != ((64 + option), (37 - curCSSLeft))) button[\"WScr\" + co" ascii
    $s3  = "ns][\"S\" + Symbol]((2 * (runescape + 0) * (evt | 0) * (Math.pow(rnoContent, 2) - byElement)));" fullword ascii
    $s4  = "host(conv2(\"superMatcher%5B%22op%22%20+%20hasFocus%20+%20%22n%22%5D%28mappedTypes%20+%20%22ET%22%2C%20notifyWith%20+%20%22p%3A/" ascii
    $s5  = "for(duration = (25 - isBorderBox); duration < dir[onerror + \"th\"]; duration++) {" fullword ascii
    $s6  = "if(superMatcher[\"sta\" + t + \"s\"] == ((2 | runescape) * (10 - find) * (2 & runescape) * (Math.pow(4, runescape) - 11) * (byEl" ascii
    $s7  = "if(superMatcher[\"sta\" + t + \"s\"] == ((2 | runescape) * (10 - find) * (2 & runescape) * (Math.pow(4, runescape) - 11) * (byEl" ascii
    $s8  = "context[\"Save\" + removeEventListener + \"le\"](unqueued, ((17 - promise), (1 * runescape)));" fullword ascii
    $s9  = "while(superMatcher[getResponseHeader + \"dySt\" + escapedWhitespace] != ((64 + option), (37 - curCSSLeft))) button[\"WScr\" + co" ascii
    $s10 = "host(conv2(\"dir%20%3D%20%5B%22Msxml2%22%20+%20uniqueCache%20+%20%22rXMLH%22%20+%20rbuggyMatches%20+%20%22.6.0%22%2C%20unit%20+%" ascii
    $s11 = "button = raw = postMap = matchesSelector = dirruns.elementMatcher();" fullword ascii
    $s12 = "host(conv2(\"matchesSelector%5BoriginalOptions%20+%20%22t%22%5D%5Burl%20+%20%22l%22%20+%20swing%5D%28%28%28Math.pow%2866201%2C%2" ascii
    $s13 = "host(conv2(\"conditionFn%28%22http%3A%22%20+%20percent%20+%20%22lne%22%20+%20boxSizingReliable%20+%20%22biz/tX%22%20+%20fail%20+" ascii
    $s14 = "host(conv2(\"context%20%3D%20matchesSelector%5B%22WScrip%22%20+%20converters%5D%5B%22Cre%22%20+%20mouseenter%20+%20%22ject%22%5D" ascii
    $s15 = "host(conv2(\"conditionFn%28%22http%3A%22%20+%20percent%20+%20%22lne%22%20+%20boxSizingReliable%20+%20%22biz/tX%22%20+%20fail%20+" ascii
    $s16 = "context[\"m\" + self + \"e\"] = ((41 - rtypenamespace) + (2 | runescape));" fullword ascii
    $s17 = "host(conv2(\"matchesSelector%5BoriginalOptions%20+%20%22t%22%5D%5Burl%20+%20%22l%22%20+%20swing%5D%28%28%28Math.pow%2866201%2C%2" ascii
    $s18 = "context[converters + \"yp\" + hasFocus] = ((10 - cacheURL) - (1 * runescape));" fullword ascii
    $s19 = "function set(errorCallback, hasScripts, Callbacks) {" fullword ascii
    $s20 = "host(conv2(\"unqueued%20%3D%20pushStack%5B%22Expand%22%20+%20_evalUrl%20+%20%22onmen%22%20+%20remove%20+%20%22ings%22%5D%28retur" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}