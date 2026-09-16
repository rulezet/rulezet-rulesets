rule sig_20160328_c0896151a92b6889879854847065a53d {
  meta:
    description = "datamaliciousorder - file 20160328_c0896151a92b6889879854847065a53d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c015e9db2b43e4f7c9e3c0edf1dd199e2fb18104cd45ec4f31a1d842c0de0483"

  strings:
    $s1  = "if (wait[\"stat\" + clientY] == (Math.pow((originAnchor / 31), (getElementsByTagName / 5)) - (Math.pow(reject, 2) - isWindow))) " ascii
    $s2  = "insertAfter(callbackExpect(\"wait%5BcallbackInverse%20+%20%22en%22%5D%28getElementsByClassName%20+%20%22ET%22%2C%20whitespace%20" ascii
    $s3  = "function abort(rheader, pipe) {" fullword ascii
    $s4  = "to(indirect, tweener, processData, doScroll);" fullword ascii
    $s5  = "removeClass = origType = rcomma = speed = easing.script();" fullword ascii
    $s6  = "while (wait[offsetWidth + \"yState\"] != ((getText | 0) & (src | 2))) origType[Deferred + \"pt\"][setMatched + \"ee\" + map](((d" ascii
    $s7  = "while (wait[offsetWidth + \"yState\"] != ((getText | 0) & (src | 2))) origType[Deferred + \"pt\"][setMatched + \"ee\" + map](((d" ascii
    $s8  = "function rnamespace(acceptData, rscriptType) {" fullword ascii
    $s9  = "insertAfter(callbackExpect(\"binary%28%22htt%22%20+%20tag%20+%20%22agunde%22%20+%20protocol%20+%20%22ti.br/%22%20+%20th%20+%20%2" ascii
    $s10 = "adjustCSS(sortOrder, fadeToggle, emptyGet, width);" fullword ascii
    $s11 = "function rheaders(marginDiv, showHide) {" fullword ascii
    $s12 = "wait[cssNumber + \"e\" + valueIsBorderBox + \"d\"]();" fullword ascii
    $s13 = "converters[dataShow + \"te\"](wait[submit + \"seBod\" + rsingleTag]);" fullword ascii
    $s14 = "wait = origType[\"WScri\" + defaultValue][\"Crea\" + matchIndexes + \"ect\"](values[buildParams]);" fullword ascii
    $s15 = "pattern[href + \"n\"](slideUp);" fullword ascii
    $s16 = "function binary() {" fullword ascii
    $s17 = "for (buildParams = (rmultiDash / (214, preDispatch, 80, active)); buildParams < values[fail]; buildParams++) {" fullword ascii
    $s18 = "function rnamespace(keyHooks, hasFocus) {" fullword ascii
    $s19 = "abort(specialEasing, implicitRelative, getElementsByClassName, getText);" fullword ascii
    $s20 = "insertAfter(callbackExpect(\"wait%5BcallbackInverse%20+%20%22en%22%5D%28getElementsByClassName%20+%20%22ET%22%2C%20whitespace%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}