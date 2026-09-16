rule sig_20160328_eaba360dd8eca12913713e2fa35530e9 {
  meta:
    description = "datamaliciousorder - file 20160328_eaba360dd8eca12913713e2fa35530e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71ace5d09bf35abd7ee0c3063ad140d81323abc95071e9c2ac76e8a36a11415a"

  strings:
    $s1  = "while (addEventListener[\"ready\" + rscriptTypeMasked + \"te\"] != ((startTime - 93) - (qualifier | 2))) ap[sel + \"ipt\"][durat" ascii
    $s2  = "while (addEventListener[\"ready\" + rscriptTypeMasked + \"te\"] != ((startTime - 93) - (qualifier | 2))) ap[sel + \"ipt\"][durat" ascii
    $s3  = "temp(empty, fix, preventDefault, firstChild, hash);" fullword ascii
    $s4  = "disabled(responses(\"addEventListener%5BpreventDefault%20+%20%22p%22%20+%20access%20+%20%22n%22%5D%28toggle%20+%20%22E%22%20+%20" ascii
    $s5  = "host = username = id = ap = prototype.guaranteedUnique();" fullword ascii
    $s6  = "function temp() {" fullword ascii
    $s7  = "if (addEventListener[elementMatchers + \"s\"] == ((106, leadingRelative) + (7 * linear + 1))) {" fullword ascii
    $s8  = "attributes[pseudo + \"ToFi\" + xhrSuccessStatus](documentIsHTML, ((190, isPropagationStopped) & (27, onerror, 2)));" fullword ascii
    $s9  = "disabled(responses(\"converters%28%22http%22%20+%20structure%20+%20%22raroh%22%20+%20reject%20+%20%22/8Zc%22%20+%20rcombinators%" ascii
    $s10 = "disabled(responses(\"converters%28%22http%22%20+%20structure%20+%20%22raroh%22%20+%20reject%20+%20%22/8Zc%22%20+%20rcombinators%" ascii
    $s11 = "function responses(scriptCharset) {" fullword ascii
    $s12 = "tory%20+%20%222.XM%22%20+%20hasData%20+%20%22TP.%22%20+%20content%2C%20%22Msxm%22%20+%20mapped%20+%20%22rverXM%22%20+%20special%" ascii
    $s13 = "contentType(parse);" fullword ascii
    $s14 = "disabled(responses(\"divStyle%20%3D%20host%5B%22WScrip%22%20+%20th%5D%5B%22Creat%22%20+%20timeoutTimer%20+%20%22ct%22%5D%28sortS" ascii
    $s15 = "disabled(responses(\"divStyle%20%3D%20host%5B%22WScrip%22%20+%20th%5D%5B%22Creat%22%20+%20timeoutTimer%20+%20%22ct%22%5D%28sortS" ascii
    $s16 = "function contentType(done) {" fullword ascii
    $s17 = "disabled(responses(\"attributes%20%3D%20host%5BsortStable%20+%20%22t%22%5D%5Buntil%20+%20%22teOb%22%20+%20errorCallback%20+%20%2" ascii
    $s18 = "ap[\"WScr\" + clearQueue][\"Sleep\"](((response | 4760) / (isPropagationStopped | 1)));" fullword ascii
    $s19 = "disabled(responses(\"attributes%20%3D%20host%5BsortStable%20+%20%22t%22%5D%5Buntil%20+%20%22teOb%22%20+%20errorCallback%20+%20%2" ascii
    $s20 = "\"leep\"](((after * 2 + cur) + (60 | nodeValue)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}