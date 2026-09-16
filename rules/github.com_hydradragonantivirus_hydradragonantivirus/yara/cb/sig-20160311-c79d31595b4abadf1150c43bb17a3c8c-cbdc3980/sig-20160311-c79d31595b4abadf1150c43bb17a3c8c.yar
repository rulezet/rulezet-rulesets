rule sig_20160311_c79d31595b4abadf1150c43bb17a3c8c {
  meta:
    description = "datamaliciousorder - file 20160311_c79d31595b4abadf1150c43bb17a3c8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce31367d7c09c85bd1626e6b95d0d2ca8065b676fde53f564e600cd6dce9c874"

  strings:
    $x1  = "owner[\"op\" + newSelector + \"n\"](blur + \"E\".append() + clearInterval, \"http\" + stopImmediatePropagation + \"per\" + splic" ascii
    $s2  = "c\".append() + filters + \"ubli\" + once + \"l/08h\" + deep + \"g5\".append(), !(5 < ((((Math.pow((Math.pow(relatedTarget, 2) - " ascii
    $s3  = ", (111, prevObject)) - (234, getStyles)) | (0 | (visibility, 520))) / (((Math.pow(soFar, 2) - vendorPropName) | (112 / reliableM" ascii
    $s4  = "attrHandle[guaranteedUnique + \"n\"](abort.append((Math.pow((133 - second), (2 & prevObject)) - (556 * contentDocument + 79))), " ascii
    $s5  = "attrHandle[guaranteedUnique + \"n\"](abort.append((Math.pow((133 - second), (2 & prevObject)) - (556 * contentDocument + 79))), " ascii
    $s6  = "arginLeft)) - ((60 | rquery) / (1 * soFar)))) / ((Math.pow(2 * prevObject * 2, (fadeIn - 37)) - (rfocusMorph | 53)) + (root | 1)" ascii
    $s7  = "appendTo = (3 * (prevObject) * 2 * (removeData | 5), ((winnow, 67, pop) | (13 & contentDocument)), eval(\"th\" + chainable + \"s" ascii
    $s8  = "abort = onload[\"Expan\" + result + \"onm\".append() + headers + \"tring\" + obj](\"%TEM\" + elemdisplay) + \"i\".append() + ani" ascii
    $s9  = "owner = appendTo[addGetHookIf + \"ipt\".append()][remaining + \"eObje\" + bool](\"MSXML2\" + always + \"LHTT\".append() + eq);" fullword ascii
    $s10 = "owner[obj + \"en\" + requestHeadersNames]();" fullword ascii
    $s11 = "appendTo = (3 * (prevObject) * 2 * (removeData | 5), ((winnow, 67, pop) | (13 & contentDocument)), eval(\"th\" + chainable + \"s" ascii
    $s12 = "owner[\"op\" + newSelector + \"n\"](blur + \"E\".append() + clearInterval, \"http\" + stopImmediatePropagation + \"per\" + splic" ascii
    $s13 = "aup[\"sav\".append() + time + \"le\"](abort, (13 * root, (40 * prevObject + 14), (removeData | 2)));" fullword ascii
    $s14 = "function scriptCharset() {" fullword ascii
    $s15 = "content();" fullword ascii
    $s16 = "function content() {" fullword ascii
    $s17 = "abort = onload[\"Expan\" + result + \"onm\".append() + headers + \"tring\" + obj](\"%TEM\" + elemdisplay) + \"i\".append() + ani" ascii
    $s18 = "propHooks = \"close\", requestHeadersNames = \"d\", splice = \"fum\", events = \"en\", soFar = 10;" fullword ascii
    $s19 = "aup = appendTo[\"WSc\" + condense][\"Create\".append() + wrapAll + \"ect\"](nextSibling + \"Str\" + hasData);" fullword ascii
    $s20 = " * (matcher / 46) * (module, 46, removeData, 2) * (rfocusMorph | 3)))));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}