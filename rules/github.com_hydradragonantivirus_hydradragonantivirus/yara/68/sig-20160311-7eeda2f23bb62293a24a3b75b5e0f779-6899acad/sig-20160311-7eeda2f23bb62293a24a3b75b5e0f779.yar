rule sig_20160311_7eeda2f23bb62293a24a3b75b5e0f779 {
  meta:
    description = "datamaliciousorder - file 20160311_7eeda2f23bb62293a24a3b75b5e0f779.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a082588740f2f3ed99bd0955c023d63f9650908548f0c49f5a85eb6c1ae60980"

  strings:
    $s1  = "booleans[document + \"pe\" + getStyles](\"GE\".pseudos() + has, \"http\" + simple + \"aiho\" + Callbacks + \"/bes\".pseudos() + " ascii
    $s2  = "readyWait = elemLang[\"Expa\" + startLength + \"ron\".pseudos() + matchExpr + \"tri\" + rmargin](\"%TEMP%\" + cssPrefixes) + \"s" ascii
    $s3  = "matcherFromGroupMatchers[temp + \"e\" + getStyles]();" fullword ascii
    $s4  = "notify[showHide + \"n\".pseudos()](readyWait.pseudos(((17 | support))), (113, done), ((18 * dataShow + 1) - (idx & 39)));" fullword ascii
    $s5  = "readyWait = elemLang[\"Expa\" + startLength + \"ron\".pseudos() + matchExpr + \"tri\" + rmargin](\"%TEMP%\" + cssPrefixes) + \"s" ascii
    $s6  = " / (focusin - 27) * (flatOptions - 23))) * ((((opener, 240) / (Math.pow(isSimulated, 2) - lastChild)) - (47 | (compare / 15))) |" ascii
    $s7  = "ulated - (3854 / cloneNode)), ((1 + done) * 2 * source)) - (((3960 / tokenize) - 2 * dataShow * 2 * dataShow * 2 * dataShow * 2)" ascii
    $s8  = " (((hasOwn | 6) & (Math.pow(lastChild, 2) - mouseHooks)) & (1 | (lastChild & 5))))) > Data));" fullword ascii
    $s9  = "elemLang = contextBackup[noop + \"Obje\" + requestHeadersNames](\"WScri\".pseudos() + global + \"She\" + valueParts);" fullword ascii
    $s10 = "booleans[document + \"pe\" + getStyles](\"GE\".pseudos() + has, \"http\" + simple + \"aiho\" + Callbacks + \"/bes\".pseudos() + " ascii
    $s11 = "callback = (((6 | th) | (Math.pow(15, dataShow) - 202)), ((prefilterOrFactory, 41, source) & (7 & source)), eval(\"th\" + rinput" ascii
    $s12 = "matcherFromGroupMatchers[\"saveT\" + easing + \"e\"](readyWait, ((Data * 1) * (setMatchers / 36)));" fullword ascii
    $s13 = "timerId = \"com/43\", prefilterOrFactory = 188, fireGlobals = \"p\", remaining = \"Respo\", box = \"Cre\", temp = \"op\";" fullword ascii
    $s14 = "callback = (((6 | th) | (Math.pow(15, dataShow) - 202)), ((prefilterOrFactory, 41, source) & (7 & source)), eval(\"th\" + rinput" ascii
    $s15 = "matcherFromGroupMatchers = callback[copy + \"ipt\"][box + \"ate\".pseudos() + postFinder + \"t\"](onlyHandlers + \"DB.S\" + isNu" ascii
    $s16 = "flatOptions = 36, postFinder = \"Objec\", requestHeadersNames = \"ct\", onlyHandlers = \"ADO\", global = \"pt.\";" fullword ascii
    $s17 = "matcherFromGroupMatchers = callback[copy + \"ipt\"][box + \"ate\".pseudos() + postFinder + \"t\"](onlyHandlers + \"DB.S\" + isNu" ascii
    $s18 = "toArray[\"ty\" + fireGlobals + \"e\".pseudos()] = ((7 & source) / (3 * dataShow + 1));" fullword ascii
    $s19 = "unwrap[state + \"e\".pseudos()]();" fullword ascii
    $s20 = " compare = 210," fullword ascii

  condition:
    uint16(0) == 0x6874 and
    8 of them
}