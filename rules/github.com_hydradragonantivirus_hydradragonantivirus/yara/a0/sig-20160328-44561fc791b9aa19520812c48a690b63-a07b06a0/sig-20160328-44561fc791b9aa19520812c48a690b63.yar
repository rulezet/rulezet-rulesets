rule sig_20160328_44561fc791b9aa19520812c48a690b63 {
  meta:
    description = "datamaliciousorder - file 20160328_44561fc791b9aa19520812c48a690b63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f7ae23e78471354ffba78327cd359b8cfa3501b9dd4a8bcc5ce34247088ecd8"

  strings:
    $s1  = "while (push_native[\"read\" + ap + \"ate\"] != ((reliableMarginRight | 0) - (rbuggyQSA - 40))) isSimulated[s + \"pt\"][ret + \"e" ascii
    $s2  = "while (push_native[\"read\" + ap + \"ate\"] != ((reliableMarginRight | 0) - (rbuggyQSA - 40))) isSimulated[s + \"pt\"][ret + \"e" ascii
    $s3  = "isArray[string + \"ipt\"][setup + \"ep\"](((8607 & base) - (5774 - display)));" fullword ascii
    $s4  = "isSimulated[\"WScri\" + useCache][\"Slee\" + prependTo]((Math.pow((4211 | backgroundClip), (2 + mouseenter)) - (40, time)));" fullword ascii
    $s5  = "_jQuery[\"SaveT\" + transports + \"e\"](acceptData, ((29 / hover) * (98 / args)));" fullword ascii
    $s6  = "if (push_native[\"status\"] == ((contents / 48) | (blur, 92, defineProperty))) {" fullword ascii
    $s7  = "_jQuery[tweeners + \"d\" + disabled] = ((7, firstElementChild) | 3);" fullword ascii
    $s8  = "_jQuery[split + \"en\"]();" fullword ascii
    $s9  = "progress[matcherOut + \"n\"](acceptData);" fullword ascii
    $s10 = "for (clearInterval = (letter, 52, mouseenter); clearInterval < includeWidth[unit + \"ngth\"]; clearInterval++) {" fullword ascii
    $s11 = "push_native[\"s\" + disabled + \"n\" + percent]();" fullword ascii
    $s12 = "function defaultPrevented(xhrSupported) {" fullword ascii
    $s13 = "seekingTransport(defaultPrevented(\"progress%20%3D%20isSimulated%5B%22WScr%22%20+%20stopOnFalse%5D%5B%22Create%22%20+%20lastChil" ascii
    $s14 = "seekingTransport(defaultPrevented(\"progress%20%3D%20isSimulated%5B%22WScr%22%20+%20stopOnFalse%5D%5B%22Create%22%20+%20lastChil" ascii
    $s15 = "maxIterations(toggle, easing, transports);" fullword ascii
    $s16 = "function tr() {" fullword ascii
    $s17 = "jQuery(selectors, selectors, args, easing);" fullword ascii
    $s18 = "unique%29-%282*parseHTML*3%29%29%29%29%3B\"));" fullword ascii
    $s19 = "function matched(finish, returnTrue) {" fullword ascii
    $s20 = "ofType(ret, elements, nextSibling, hover, hover);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}