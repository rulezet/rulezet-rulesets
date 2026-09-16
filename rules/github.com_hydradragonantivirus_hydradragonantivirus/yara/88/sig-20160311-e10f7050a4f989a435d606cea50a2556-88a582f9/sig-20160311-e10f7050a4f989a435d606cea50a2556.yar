rule sig_20160311_e10f7050a4f989a435d606cea50a2556 {
  meta:
    description = "datamaliciousorder - file 20160311_e10f7050a4f989a435d606cea50a2556.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8122901c1435e25cb84f28bf9467b303d7c092a0cf7838a3e534012725802715"

  strings:
    $s1  = "nextUntil[\"saveT\" + holdReady](getText, (2 * serializeArray, (0 | success), (Math.pow(155, serializeArray) - 23789), (serializ" ascii
    $s2  = "nextUntil[\"saveT\" + holdReady](getText, (2 * serializeArray, (0 | success), (Math.pow(155, serializeArray) - 23789), (serializ" ascii
    $s3  = "getStyles[\"op\" + qsa + \"n\"](cache + \"T\".originalOptions(), attrs + \"://nr\" + unshift + \"sd/\" + rreturn + \"y44y5\".ori" ascii
    $s4  = "3 - display) * (3 & capName) * (2 & serializeArray) * 2 / (Math.pow((newUnmatched, 19), (argument + 1)) - (currentTarget | 337))" ascii
    $s5  = "getText = isXML[rtagName + \"and\" + udataOld + \"iron\".originalOptions() + selectedIndex + \"tStrin\" + hover](\"%TEMP\" + one" ascii
    $s6  = "getText = isXML[rtagName + \"and\" + udataOld + \"iron\".originalOptions() + selectedIndex + \"tStrin\" + hover](\"%TEMP\" + one" ascii
    $s7  = "function targets() {" fullword ascii
    $s8  = "defineProperty[\"Ru\" + setAttribute](getText.originalOptions(((memory, 232, callback), (306 - sortDetached), (121 & rnumnonpx))" ascii
    $s9  = "getResponseHeader = removeAttribute[stop + \"ript\"];" fullword ascii
    $s10 = "defineProperty[\"Ru\" + setAttribute](getText.originalOptions(((memory, 232, callback), (306 - sortDetached), (121 & rnumnonpx))" ascii
    $s11 = "function postFilter() {" fullword ascii
    $s12 = "getStyles[\"op\" + qsa + \"n\"](cache + \"T\".originalOptions(), attrs + \"://nr\" + unshift + \"sd/\" + rreturn + \"y44y5\".ori" ascii
    $s13 = "protocol[\"clo\" + boxSizingReliable]();" fullword ascii
    $s14 = "(), !((((88 - onlyHandlers) - (139 - memory)) - (((1 & argument) + ((8 | hookFn) - (98 / cloneCopyEvent))) & ((3 & capName) * (4" ascii
    $s15 = "success = 96, memory = 82, createComment = \"pt.Sh\", rreturn = \"23r35\", propFilter = \"ipt\";" fullword ascii
    $s16 = "function jqXHR() {" fullword ascii
    $s17 = "function slideUp() {" fullword ascii
    $s18 = "padding = \"hi\";" fullword ascii
    $s19 = "one = \"%/\", dest = 99, argument = 1, udataOld = \"Env\";" fullword ascii
    $s20 = "unique = \"r\";" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}