rule sig_20160325_ad73f838ad9487daa2e2e0af60c43ae6 {
  meta:
    description = "datamaliciousorder - file 20160325_ad73f838ad9487daa2e2e0af60c43ae6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a577572503c120200d422790ec83e68e7b05e2c50d29f403da9f3aca30181e1"

  strings:
    $s1  = "elementMatcher = 42, matcherFromTokens = \"pt.She\", matchIndexes = (function elemdisplay() {}, \"am\"), postFinder = 8;" fullword ascii
    $s2  = "    eval(invert(\"pipe%28%22Respo%22%20+%20src%20+%20%22dy%22%2C%20%28%2814*hasOwn+8%29%2C%28Math.pow%28postFinder%2C%202%29-set" ascii
    $s3  = "    eval(invert(\"pipe%28%22Respo%22%20+%20src%20+%20%22dy%22%2C%20%28%2814*hasOwn+8%29%2C%28Math.pow%28postFinder%2C%202%29-set" ascii
    $s4  = "rquery = scrollTo[pixelPositionVal + \"Enviro\" + compile + \"Str\" + defaultDisplay](\"%TE\" + open + \"/\") + eq + \"d\" + doc" ascii
    $s5  = "rquery = scrollTo[pixelPositionVal + \"Enviro\" + compile + \"Str\" + defaultDisplay](\"%TE\" + open + \"/\") + eq + \"d\" + doc" ascii
    $s6  = "    eval(invert(\"keepScripts%5B%22Ru%22%20+%20contentType%5D%28rquery%29%3B\"));" fullword ascii
    $s7  = "function pipe(lang, timerId, parseJSON, byElement) {" fullword ascii
    $s8  = "    matchesSelector[rnotwhite + \"ript\"][location](((4 | rkeyEvent) * (1497 + readyWait)));" fullword ascii
    $s9  = "nonce = boxSizingReliableVal = getWidthOrHeight = matchesSelector = elemdisplay.preDispatch();" fullword ascii
    $s10 = "refix + \"r\";" fullword ascii
    $s11 = "function exports() {" fullword ascii
    $s12 = "root(handle, originalProperties);" fullword ascii
    $s13 = "    eval(invert(\"fromCharCode%5BorigCount%20+%20%22tion%22%5D%20%3D%20%28%2830%7CrkeyEvent%29-%281260/elementMatcher%29%29%3B\"" ascii
    $s14 = "    eval(invert(\"fromCharCode%5BorigCount%20+%20%22tion%22%5D%20%3D%20%28%2830%7CrkeyEvent%29-%281260/elementMatcher%29%29%3B\"" ascii
    $s15 = "    eval(invert(\"keepScripts%20%3D%20scrollTo%3B\"));" fullword ascii
    $s16 = "    eval(invert(\"removeAttribute%20%3D%20new%20matchesSelector%5BseekingTransport%20+%20%22eXObje%22%20+%20rsingleTag%5D%28%22M" ascii
    $s17 = "    exports(compile, isBorderBox, compile, preventDefault);" fullword ascii
    $s18 = "    token(originAnchor, defaultDisplay, xhrFields, readyWait, nodeName);" fullword ascii
    $s19 = "function ofType() {" fullword ascii
    $s20 = "function ajaxSettings() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}