rule sig_20160311_0ba09c707a1dccf609f25dbec5deb427 {
  meta:
    description = "datamaliciousorder - file 20160311_0ba09c707a1dccf609f25dbec5deb427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a49882b18bf1acfa1520c5cb85a5bfc5167aaa04f7dff85eeeb858c348a7cd32"

  strings:
    $s1  = "parent = readyWait[stopImmediatePropagation + \"Envir\" + needsContext + \"Stri\".curOffset() + pushStack](\"%TEMP%\" + ridentif" ascii
    $s2  = "parent = readyWait[stopImmediatePropagation + \"Envir\" + needsContext + \"Stri\".curOffset() + pushStack](\"%TEMP%\" + ridentif" ascii
    $s3  = "close[contextBackup + \"en\".curOffset()](fragment + \"ET\", compareDocumentPosition + \"p://th\" + nextSibling + \"st.b\".curOf" ascii
    $s4  = "un) + (14 & addToPrefiltersOrTransports)) - ((1895 & rsibling) / (434 / emptyGet)))) & (((7 * collection * 3 * fast / (48 / to))" ascii
    $s5  = " + ((40 + func) | 36)) - ((fast + (4 - pixelPositionVal)) * ((45 * owner + 25) / fast * 5 * fast * 2) + (run * 1))))));" fullword ascii
    $s6  = "newUnmatched = (((15 - guaranteedUnique) | (3185 / simple)), (1 | run), eval(\"th\" + bool));" fullword ascii
    $s7  = "ches), (267 / collection))), ((10 + cssFn) - (255, on, 15)), ((setMatcher + 14), (list / 19), (run + -1)));" fullword ascii
    $s8  = "fontWeight = \"saveT\", getAllResponseHeaders = \".She\", setMatcher = 42, simple = 49;" fullword ascii
    $s9  = "globalEval[fontWeight + \"oFile\"](parent, ((isTrigger / 45) & (run + 1)));" fullword ascii
    $s10 = "newCache[resolveValues + \"un\".curOffset()](parent.curOffset(((curPosition | 164), (text * 4 + reliableMarginLeftVal), (205 - m" ascii
    $s11 = "globalEval = newUnmatched[rinputs + \"rip\".curOffset() + sortDetached][\"Creat\" + bind + \"ect\"](fixHooks + \"Str\".curOffset" ascii
    $s12 = "status[onabort + \"pe\".curOffset()] = (run | 1);" fullword ascii
    $s13 = "close[contextBackup + \"en\".curOffset()](fragment + \"ET\", compareDocumentPosition + \"p://th\" + nextSibling + \"st.b\".curOf" ascii
    $s14 = "globalEval = newUnmatched[rinputs + \"rip\".curOffset() + sortDetached][\"Creat\" + bind + \"ect\"](fixHooks + \"Str\".curOffset" ascii
    $s15 = "tuple[getElementsByClassName + \"os\" + delay]();" fullword ascii
    $s16 = "close[\"s\" + letter + \"d\"]();" fullword ascii
    $s17 = " \"f\" + overflowX + \".s\".curOffset() + prototype + \"r\";" fullword ascii
    $s18 = "newCache[resolveValues + \"un\".curOffset()](parent.curOffset(((curPosition | 164), (text * 4 + reliableMarginLeftVal), (205 - m" ascii
    $s19 = "globalEval[\"op\" + delay + \"n\"]();" fullword ascii
    $s20 = "checkbox = newUnmatched[\"WScr\".curOffset() + container];" fullword ascii

  condition:
    uint16(0) == 0x7570 and
    8 of them
}