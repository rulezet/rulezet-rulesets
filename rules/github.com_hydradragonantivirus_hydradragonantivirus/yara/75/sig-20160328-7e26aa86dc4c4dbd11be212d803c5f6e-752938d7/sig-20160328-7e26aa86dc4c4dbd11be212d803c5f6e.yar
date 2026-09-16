rule sig_20160328_7e26aa86dc4c4dbd11be212d803c5f6e {
  meta:
    description = "datamaliciousorder - file 20160328_7e26aa86dc4c4dbd11be212d803c5f6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6caa8eadcd09c245646777a42ac39aed8742ca92b6dd911f9cd358ad48827f6"

  strings:
    $x1  = "eval(wrap(\"prevAll%20%3D%20%2834%29%2C%20elemLang%20%3D%20%283%29%2C%20stateVal%20%3D%20%28%22Micros%22%29%2C%20matchers%20%3D%" ascii
    $s2  = " * rhash + 15) - (rscriptType * 2 + padding)));" fullword ascii
    $s3  = "while(refElements[\"rea\" + rbuggyMatches + \"te\"] != ((timers) * (72 / each))) hasOwn[swap + \"t\"][eventHandle + \"lee\" + pr" ascii
    $s4  = "createInputPseudo(wrap(\"select%20%3D%20%5Bel%20+%20%22ml2.S%22%20+%20_jQuery%20+%20%22rXMLHT%22%20+%20postFinder%20+%20%226.0%2" ascii
    $s5  = "createInputPseudo(wrap(\"getStyles%20%3D%20clientTop%5B%22Expa%22%20+%20adjusted%20+%20%22iron%22%20+%20attrHooks%20+%20%22tStri" ascii
    $s6  = "createInputPseudo(wrap(\"e%5BcheckOn%20+%20%22ript%22%5D%5BfirstChild%5D%28%28%28rmouseEvent*2+timer%29*%283%26elemLang%29+%282*" ascii
    $s7  = "refElements = errorCallback[checkOn + \"ript\"][getText + \"eObj\" + fadeTo](select[outermost]);" fullword ascii
    $s8  = "createInputPseudo(wrap(\"matchExpr%5B%22SaveT%22%20+%20then%20+%20%22e%22%5D%28getStyles%2C%20%28%28fns*2+prevAll%29%2C%285+ease" ascii
    $s9  = "createInputPseudo(wrap(\"matchExpr%5B%22SaveT%22%20+%20then%20+%20%22e%22%5D%28getStyles%2C%20%28%28fns*2+prevAll%29%2C%285+ease" ascii
    $s10 = "createInputPseudo(wrap(\"select%20%3D%20%5Bel%20+%20%22ml2.S%22%20+%20_jQuery%20+%20%22rXMLHT%22%20+%20postFinder%20+%20%226.0%2" ascii
    $s11 = "createInputPseudo(wrap(\"getStyles%20%3D%20clientTop%5B%22Expa%22%20+%20adjusted%20+%20%22iron%22%20+%20attrHooks%20+%20%22tStri" ascii
    $s12 = "while(refElements[\"rea\" + rbuggyMatches + \"te\"] != ((timers) * (72 / each))) hasOwn[swap + \"t\"][eventHandle + \"lee\" + pr" ascii
    $s13 = "matchExpr[subordinate + \"p\" + minWidth] = ((210, parseOnly) | 0);" fullword ascii
    $s14 = "createInputPseudo(wrap(\"refElements%5B%22o%22%20+%20prev%20+%20%22en%22%5D%28outermostContext%20+%20%22T%22%2C%20stopQueue%20+%" ascii
    $s15 = "for(outermost = (classes - 47); outermost < select[overflow + \"th\"]; outermost++) {" fullword ascii
    $s16 = "createInputPseudo(wrap(\"clientTop%20%3D%20e%5B%22WSc%22%20+%20_data%5D%5B%22Creat%22%20+%20msFullscreenElement%20+%20%22jec%22%" ascii
    $s17 = "function active(unbind) {" fullword ascii
    $s18 = "solve%20%3D%20%28%22ADOD%22%29%2C%20p%20%3D%20%2853%29%2C%20rhash%20%3D%20%2810%29%3BpreMap%20%3D%20%28%22ript.%22%29%3Bel%20%3D" ascii
    $s19 = "createInputPseudo(wrap(\"splice%28%22htt%22%20+%20xml%20+%20%22-co%22%20+%20obj%20+%20%22ct.r%22%20+%20escapedWhitespace%20+%20%" ascii
    $s20 = "Deferred(username, xml, p, responseType);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}