rule sig_20160329_defa5a17a87129777715ee7503066f16 {
  meta:
    description = "datamaliciousorder - file 20160329_defa5a17a87129777715ee7503066f16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc3e0d75c25c4f116f62c477edc8796b5c3ccd291eb616c8c4bf12067850ba4"

  strings:
    $s1  = "for (i = (apply | 0); i < rbrace[getScript + \"ngth\"]; i++) {" fullword ascii
    $s2  = "seed(\"rbrace%20%3D%20%5Bpattern%20+%20%22l2.S%22%20+%20parentsUntil%20+%20%22XMLH%22%20+%20siblings%20+%20%22.0%22%2C%20pattern" ascii
    $s3  = "matcherFromGroupMatchers[\"mo\" + duration] = ((Math.pow(44, selector) - 1887) - (unwrap, 126, document, 46));" fullword ascii
    $s4  = "function seed(relatedTarget) {" fullword ascii
    $s5  = "sports%2C%22Msx%22%20+%20curOffset%20+%20%22XMLHT%22%20+%20rcleanScript%2C%20%22Msxml%22%20+%20preMap%20+%20%22TTP%22%2C%20conv%" ascii
    $s6  = "matcherFromGroupMatchers[\"SaveTo\" + responseHeaders](innerText, ((1 | stored) * (1 * selector)));" fullword ascii
    $s7  = "seed(\"overflow%5B%22o%22%20+%20rneedsContext%20+%20%22e%22%20+%20seekingTransport%5D%28%22G%22%20+%20getById%20+%20%22T%22%2C%2" ascii
    $s8  = "function jsonp(special, getText, isReady) {" fullword ascii
    $s9  = "seed(\"overflow%5B%22o%22%20+%20rneedsContext%20+%20%22e%22%20+%20seekingTransport%5D%28%22G%22%20+%20getById%20+%20%22T%22%2C%2" ascii
    $s10 = "function script() {" fullword ascii
    $s11 = "seed(\"matcherFromGroupMatchers%20%3D%20bup%5BeventPath%20+%20%22ipt%22%5D%5BpageX%20+%20%22Objec%22%20+%20isTrigger%5D%28%22ADO" ascii
    $s12 = "seed(\"innerText%20%3D%20hasOwn%5B%22Expa%22%20+%20deep%20+%20%22nvi%22%20+%20leadingRelative%20+%20%22men%22%20+%20ajaxPrefilte" ascii
    $s13 = "return shift(unescape(relatedTarget));" fullword ascii
    $s14 = "script(hasFocus, leadingRelative, firstChild);" fullword ascii
    $s15 = "getBoundingClientRect(matcher);" fullword ascii
    $s16 = "function getBoundingClientRect(merge, MAX_NEGATIVE, globalEval) {" fullword ascii
    $s17 = "overflow[\"s\" + fired + \"n\" + cssShow]();" fullword ascii
    $s18 = "matcherFromGroupMatchers[\"Writ\" + fired](overflow[\"respon\" + scrollLeft + \"y\"]);" fullword ascii
    $s19 = "matcherFromGroupMatchers[\"t\" + dataType + \"e\"] = ((stored | 1) & (reject / 34));" fullword ascii
    $s20 = "overflow = err[eventPath + \"ipt\"][pageX + \"Obj\" + fire](rbrace[i]);" fullword ascii

  condition:
    uint16(0) == 0x7469 and
    8 of them
}