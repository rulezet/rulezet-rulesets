rule sig_20160328_12ff1869100bdf488c8ea5e09a5d5d81 {
  meta:
    description = "datamaliciousorder - file 20160328_12ff1869100bdf488c8ea5e09a5d5d81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c795696a14767ddb8041fb0b8ae646a17a38d633443744dc3f9d88ad5a6a648b"

  strings:
    $x1  = "eval(margin(\"elemData%20%3D%20%28%22.%22%29%2C%20needsContext%20%3D%20%2820%29%3Bwin%20%3D%20%28function%20parseHTML%28%29%7B%7" ascii
    $s2  = "while (tuples[\"read\" + disableScript + \"e\"] != ((winnow + 0) + pos)) button[checked + \"ript\"][parseFromString]((Math.pow((" ascii
    $s3  = "tuples = button[\"WScrip\" + newSelector][\"Crea\" + currentTarget + \"ject\"](username[setMatcher]);" fullword ascii
    $s4  = "display(margin(\"username%20%3D%20%5B%22Msxml2%22%20+%20nodes%20+%20%22erX%22%20+%20until%20+%20%22.6.%22%20+%20camelCase%2C%20%" ascii
    $s5  = "for (setMatcher = ((5 & checkNonElements) - 5); setMatcher < username[version + \"eng\" + groups]; setMatcher++) {" fullword ascii
    $s6  = "while (tuples[\"read\" + disableScript + \"e\"] != ((winnow + 0) + pos)) button[checked + \"ript\"][parseFromString]((Math.pow((" ascii
    $s7  = "uccess + 4), (firing & 3)) - (parseJSON * 4 + addEventListener)));" fullword ascii
    $s8  = "button[checked + \"ript\"][round + \"p\"](((Math.pow(4142, firing) - 17151428) | (defaultView / 29)));" fullword ascii
    $s9  = "display(margin(\"hash%28%22htt%22%20+%20teardown%20+%20%22rbuz-%22%20+%20rheader%20+%20%22ru/a5%22%20+%20dest%20+%20%22xe%22%29%" ascii
    $s10 = "currentValue[\"ty\" + curPosition] = ((9 - selectedIndex) + (0 & winnow));" fullword ascii
    $s11 = "if (tuples[\"stat\" + showHide] == (2 * (needsContext, 175, inPage, 5) * (buildFragment - 17) * (winnow * 2) * (pdataOld - 49)))" ascii
    $s12 = "display(margin(\"hash%28%22htt%22%20+%20teardown%20+%20%22rbuz-%22%20+%20rheader%20+%20%22ru/a5%22%20+%20dest%20+%20%22xe%22%29%" ascii
    $s13 = "display(margin(\"slow%20%3D%20camelKey%5B%22Expa%22%20+%20write%20+%20%22iro%22%20+%20completed%20+%20%22tri%22%20+%20slideDown%" ascii
    $s14 = "function beforeSend(requestHeaders) {" fullword ascii
    $s15 = "pageY(checked, prevUntil, textContent);" fullword ascii
    $s16 = "p(always, off, postFinder, clazz);" fullword ascii
    $s17 = "display(margin(\"currentValue%20%3D%20a%5BtextContent%20+%20%22pt%22%5D%5Boff%20+%20%22teOb%22%20+%20fxNow%5D%28%22ADO%22%20+%20" ascii
    $s18 = "display(margin(\"currentValue%20%3D%20a%5BtextContent%20+%20%22pt%22%5D%5Boff%20+%20%22teOb%22%20+%20fxNow%5D%28%22ADO%22%20+%20" ascii
    $s19 = "currentValue[\"op\" + when]();" fullword ascii
    $s20 = "currentValue[fired + \"oFile\"](slow, ((2 & pos)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}