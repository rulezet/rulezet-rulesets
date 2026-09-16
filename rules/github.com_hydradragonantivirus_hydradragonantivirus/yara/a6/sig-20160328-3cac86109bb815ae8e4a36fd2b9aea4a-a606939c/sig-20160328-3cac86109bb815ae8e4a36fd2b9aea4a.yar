rule sig_20160328_3cac86109bb815ae8e4a36fd2b9aea4a {
  meta:
    description = "datamaliciousorder - file 20160328_3cac86109bb815ae8e4a36fd2b9aea4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7289b3b13ca70201a9dbe9828b07bc726438e430e608064de3ea8e5fd514f58e"

  strings:
    $x1  = "eval(ofType(\"extra%20%3D%20%28%22Msx%22%29%3B%20buildParams%20%3D%20%28%22nd%22%29%3B%20has%20%3D%20%28%22.XMLH%22%29%3B%20optS" ascii
    $s2  = "scriptCharset[merge + \"eToFi\" + seekingTransport](until, ((33, handleObj) / (Math.pow(31, disable) - 911)));" fullword ascii
    $s3  = "binary[\"WSc\" + innerHTML][\"Sleep\"](((type - 119), (getStyles * 17 + disable), (218, timeout)));" fullword ascii
    $s4  = "scriptCharset[\"t\" + postMap + \"e\"] = ((254, fireGlobals, 1, tweener) | (0 / firing));" fullword ascii
    $s5  = "scriptCharset[after + \"d\" + rbuggyQSA] = ((45 - valueIsBorderBox) - (30 | tfoot));" fullword ascii
    $s6  = "if (maxIterations[serializeArray] == (Math.pow((3171 / animation), (2 | rsubmittable)) - (Math.pow(21887, disable) - 479018168))" ascii
    $s7  = "while (maxIterations[\"rea\" + lname + \"ate\"] != ((disable & 2) * (tweener * 2))) domManip[image + \"pt\"][tick + \"eep\"](((M" ascii
    $s8  = "if (maxIterations[serializeArray] == (Math.pow((3171 / animation), (2 | rsubmittable)) - (Math.pow(21887, disable) - 479018168))" ascii
    $s9  = "insertAfter(ofType(\"until%20%3D%20id%5B%22Expan%22%20+%20getWidthOrHeight%20+%20%22onment%22%20+%20delegateTarget%20+%20%22ngs%" ascii
    $s10 = "id[\"R\" + pipe](until);" fullword ascii
    $s11 = "insertAfter(ofType(\"until%20%3D%20id%5B%22Expan%22%20+%20getWidthOrHeight%20+%20%22onment%22%20+%20delegateTarget%20+%20%22ngs%" ascii
    $s12 = "w, 2) - resolve) * (10 / makeArray) * (2 + rsubmittable) * (3, makeArray)));" fullword ascii
    $s13 = "for (_removeData = ((29 - filter) + -(1 * tweener)); _removeData < code[\"l\" + rbuggyQSA + \"n\" + settings]; _removeData++) {" fullword ascii
    $s14 = "while (maxIterations[\"rea\" + lname + \"ate\"] != ((disable & 2) * (tweener * 2))) domManip[image + \"pt\"][tick + \"eep\"](((M" ascii
    $s15 = "insertAfter(ofType(\"current%5B%22WScrip%22%20+%20hookFn%5D%5B%22S%22%20+%20values%5D%28%28%28optSelected/19%29-%28getStyles*2*m" ascii
    $s16 = "function ofType(addGetHookIf) {" fullword ascii
    $s17 = "insertAfter(ofType(\"current%5B%22WScrip%22%20+%20hookFn%5D%5B%22S%22%20+%20values%5D%28%28%28optSelected/19%29-%28getStyles*2*m" ascii
    $s18 = "maxIterations = domManip[\"WScri\" + createTextNode][\"Create\" + parents + \"ect\"](code[_removeData]);" fullword ascii
    $s19 = "current = domManip = binary = fns = cloneNode.tweens();" fullword ascii
    $s20 = "return unescape(addGetHookIf);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}