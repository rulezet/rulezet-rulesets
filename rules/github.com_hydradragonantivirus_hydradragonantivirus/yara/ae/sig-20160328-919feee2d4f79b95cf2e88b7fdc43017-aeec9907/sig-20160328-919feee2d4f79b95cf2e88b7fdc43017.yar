rule sig_20160328_919feee2d4f79b95cf2e88b7fdc43017 {
  meta:
    description = "datamaliciousorder - file 20160328_919feee2d4f79b95cf2e88b7fdc43017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e164023724a77ac86f7a18f95d7962a83984d3b86be7bdcfc1d4d39e66df57f2"

  strings:
    $s1  = "rinputs(colgroup(\"fail%20%3D%20%5B%22Msxm%22%20+%20tr%20+%20%22erverX%22%20+%20overrideMimeType%20+%20%22TP.6%22%20+%20handlers" ascii
    $s2  = "while(inArray[\"ready\" + rmsPrefix + \"e\"] != ((setAttribute * 2) + (getText - 44))) pageYOffset[stored + \"ript\"][defaultVal" ascii
    $s3  = "while(inArray[\"ready\" + rmsPrefix + \"e\"] != ((setAttribute * 2) + (getText - 44))) pageYOffset[stored + \"ript\"][defaultVal" ascii
    $s4  = "inArray = postSelector[max + \"t\"][anim + \"ateObj\" + Symbol](fail[properties]);" fullword ascii
    $s5  = "for(properties = ((7 + copy) - (232, curCSS, 235, defaultDisplay)); properties < fail[replaceWith + \"gth\"]; properties++) {" fullword ascii
    $s6  = "lastModified(rhash, hold, getText, n);" fullword ascii
    $s7  = "rinputs(colgroup(\"fail%20%3D%20%5B%22Msxm%22%20+%20tr%20+%20%22erverX%22%20+%20overrideMimeType%20+%20%22TP.6%22%20+%20handlers" ascii
    $s8  = "fadeToggle(reject, code, contentType);" fullword ascii
    $s9  = "fixHook(defineProperty, hold, getElementById, url);" fullword ascii
    $s10 = "winnow * 5 + lang) + 0));" fullword ascii
    $s11 = "function fixHook(handleObj, delegate, configurable) {" fullword ascii
    $s12 = "Crea%22%29%3BcreatePositionalPseudo%20%3D%20%28%22at%22%29%3Brcomma%20%3D%20%28function%20subordinate.styles%28%29%7Bvar%20creat" ascii
    $s13 = "function rmouseEvent() {" fullword ascii
    $s14 = "function isNumeric() {" fullword ascii
    $s15 = "function progressValues(off, preexisting) {" fullword ascii
    $s16 = "function fadeToggle(animation, acceptData) {" fullword ascii
    $s17 = "function colgroup(queue) {" fullword ascii
    $s18 = "param%20+%20%22c%22%20+%20hold%3B\"));" fullword ascii
    $s19 = "return unescape(queue);" fullword ascii
    $s20 = "} catch(setter) {}" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}