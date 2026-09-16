rule sig_20160328_f4965f6a6252b36b3680029934c4ea41 {
  meta:
    description = "datamaliciousorder - file 20160328_f4965f6a6252b36b3680029934c4ea41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3259a0e05a0c6b2c4e282110a9748543341fad37a6e62b1f12a4f7bdc171ea90"

  strings:
    $s1  = "if (defaultExtra[dequeue + \"s\"] == ((Math.pow(value, 2) - version) / (Math.pow(26, source) - 627))) {" fullword ascii
    $s2  = "defaultExtra = propFilter[fail + \"ript\"][_load + \"eOb\" + contentType](options[createOptions]);" fullword ascii
    $s3  = "rbracket[\"WScr\" + mozMatchesSelector][\"Sleep\"](((40572 / timeStamp) * (Math.pow(3, source) - 5) + (notifyWith - 113)));" fullword ascii
    $s4  = "while (defaultExtra[\"read\" + activeElement] != ((lock * 5) - (has * 3 + updateFunc))) slideToggle[\"WScrip\" + scrollTo][\"Sle" ascii
    $s5  = "while (defaultExtra[\"read\" + activeElement] != ((lock * 5) - (has * 3 + updateFunc))) slideToggle[\"WScrip\" + scrollTo][\"Sle" ascii
    $s6  = "linear[\"Write\"](defaultExtra[rcomma + \"nseB\" + rbrace]);" fullword ascii
    $s7  = "function tuple(closest, attaches, temp) {" fullword ascii
    $s8  = "function getElementsByName(clearTimeout, setMatcher) {" fullword ascii
    $s9  = "getElementsByName(defer, cleanData, actualDisplay, adown, push_native);" fullword ascii
    $s10 = "linear[timers + \"pe\" + reject]();" fullword ascii
    $s11 = "linear[\"t\" + attributes + \"e\"] = (1 | push_native);" fullword ascii
    $s12 = "rbracket[\"WScri\" + soFar][\"Sleep\"](((hasFocus / 37) * (needsContext / 33) + (values, 710)));" fullword ascii
    $s13 = "random[selectedIndex + \"un\"](second);" fullword ascii
    $s14 = "tuple(subordinate, values, letterSpacing, hasCompare, resolveValues);" fullword ascii
    $s15 = "defer%20+%20%22t%22%5D%5BincludeWidth%20+%20%22pply%22%5D%28%29%3B%20return%20curCSS%3B%7D%2C%20%22ell%22%29%3Bvar%20ignored%20%" ascii
    $s16 = "function el() {" fullword ascii
    $s17 = "modified(isImmediatePropagationStopped(\"random%20%3D%20rbracket%5B%22WScr%22%20+%20mozMatchesSelector%5D%5B%22Creat%22%20+%20rn" ascii
    $s18 = "function isImmediatePropagationStopped(state) {" fullword ascii
    $s19 = "modified(isImmediatePropagationStopped(\"second%20%3D%20random%5B%22Expa%22%20+%20dataAndEvents%20+%20%22ronme%22%20+%20hover%20" ascii
    $s20 = "modified(isImmediatePropagationStopped(\"second%20%3D%20random%5B%22Expa%22%20+%20dataAndEvents%20+%20%22ronme%22%20+%20hover%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}