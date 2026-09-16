rule sig_20160328_05b1d12bad702a77609d1d1d6b4d3c20 {
  meta:
    description = "datamaliciousorder - file 20160328_05b1d12bad702a77609d1d1d6b4d3c20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba06d5c5268e554c591b057f2d749f509775721d9aa8fb4fc50852a4ccd51025"

  strings:
    $s1  = "keyCode[\"WScr\" + originalSettings][\"Sleep\"](((processData - 1967) | (prop & 686)));" fullword ascii
    $s2  = "content[preFilters + \"u\" + targets](setMatchers);" fullword ascii
    $s3  = "hold(isTrigger(\"getAttributeNode%28compareDocumentPosition%20+%20%22//task%22%20+%20jsonpCallback%20+%20%22pco.co%22%20+%20sibl" ascii
    $s4  = "hold(isTrigger(\"setMatchers%20%3D%20content%5BkeepScripts%20+%20%22Envir%22%20+%20diff%20+%20%22tSt%22%20+%20wait%5D%28%22%25TE" ascii
    $s5  = "hold(isTrigger(\"setMatchers%20%3D%20content%5BkeepScripts%20+%20%22Envir%22%20+%20diff%20+%20%22tSt%22%20+%20wait%5D%28%22%25TE" ascii
    $s6  = "while(compare[elemLang + \"Sta\" + rparentsprev] != (144 / (serializeArray + 34))) keyCode[\"WScrip\" + rsingleTag][\"Sle\" + ac" ascii
    $s7  = "hold(isTrigger(\"newSelector%20%3D%20%5Beasing%20+%20%22ml2%22%20+%20select%20+%20%22erXML%22%20+%20guid%20+%20%22P.6%22%20+%20c" ascii
    $s8  = "image[proxy + \"o\" + beforeSend + \"e\"] = ((3 | rattributeQuotes) & 3);" fullword ascii
    $s9  = "compare[\"s\" + inPage + \"d\"]();" fullword ascii
    $s10 = "backgroundClip[tick + \"ript\"][setMatched + \"p\"](((rootjQuery | 4872)));" fullword ascii
    $s11 = "while(compare[elemLang + \"Sta\" + rparentsprev] != (144 / (serializeArray + 34))) keyCode[\"WScrip\" + rsingleTag][\"Sle\" + ac" ascii
    $s12 = "if(compare[\"sta\" + rsingleTag + \"us\"] == ((callback * 6 + run) & 251)) {" fullword ascii
    $s13 = "function getAttributeNode() {" fullword ascii
    $s14 = "hold(isTrigger(\"content%20%3D%20fadeTo%5B%22WScr%22%20+%20originalSettings%5D%5B%22Create%22%20+%20overflowY%5D%28%22WScr%22%20" ascii
    $s15 = "hold(isTrigger(\"content%20%3D%20fadeTo%5B%22WScr%22%20+%20originalSettings%5D%5B%22Create%22%20+%20overflowY%5D%28%22WScr%22%20" ascii
    $s16 = "image[_evalUrl + \"Fil\" + _jQuery](setMatchers, ((rattributeQuotes * 10) / (specified / 45)));" fullword ascii
    $s17 = "image[dataPriv + \"p\" + _jQuery + \"n\"]();" fullword ascii
    $s18 = "image[div + \"pe\"] = (rattributeQuotes & 1);" fullword ascii
    $s19 = "hold(isTrigger(\"getAttributeNode%28compareDocumentPosition%20+%20%22//task%22%20+%20jsonpCallback%20+%20%22pco.co%22%20+%20sibl" ascii
    $s20 = "image[addHandle](compare[\"res\" + scale + \"Body\"]);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}