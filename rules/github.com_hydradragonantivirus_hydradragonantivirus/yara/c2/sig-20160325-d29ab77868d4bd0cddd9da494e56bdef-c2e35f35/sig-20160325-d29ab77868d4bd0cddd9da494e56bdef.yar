rule sig_20160325_d29ab77868d4bd0cddd9da494e56bdef {
  meta:
    description = "datamaliciousorder - file 20160325_d29ab77868d4bd0cddd9da494e56bdef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e781c39bba7d5078bcac48f1fff75c990cd3954bc4e8879387bb189f52a647c9"

  strings:
    $s1  = "pageYOffset[\"WScrip\" + doneName][\"Sl\" + temp + \"ep\"](((Math.pow(9001, status) - 81003230) - (after + 3565)));" fullword ascii
    $s2  = "eval(box(\"once%5B%22op%22%20+%20has%5D%28%22GE%22%20+%20cacheURL%2C%20%22http%3A/%22%20+%20finalText%20+%20%22servic%22%20+%20n" ascii
    $s3  = "return safeActiveElement[targets](rnotwhite, slideUp);" fullword ascii
    $s4  = "function bubbleType(rnotwhite, safeActiveElement, slideUp, targets) {" fullword ascii
    $s5  = "var pageY = [][\"con\" + selectedIndex + \"or\"][write + \"tot\" + hasContent][\"so\" + sel + \"t\"][xhr + \"ly\"]();" fullword ascii
    $s6  = "mouseHooks = \"eBody\", rtypenamespace = \"teObj\", temp = \"e\";" fullword ascii
    $s7  = "sel = \"r\", rcssNum = \"%TEMP\", expanded = \"Msxm\";" fullword ascii
    $s8  = "key = \"n.de/U\", valHooks = (function clearCloneStyle.map() {" fullword ascii
    $s9  = "eval(box(\"transport%5B%22pos%22%20+%20addEventListener%20+%20%22n%22%5D%20%3D%20%280%26%28binary+0%29%29%3B\"));" fullword ascii
    $s10 = "function postDispatch() {" fullword ascii
    $s11 = "function rnoContent() {" fullword ascii
    $s12 = "noop = parseHTML[\"WScrip\" + doneName];" fullword ascii
    $s13 = "returnTrue[\"ty\" + size + \"e\"] = ((17 / nextUntil) * (1 + invert));" fullword ascii
    $s14 = "noop[\"Sleep\"]((2 * status * 37 * status * 3 * noConflict + (2352 & old)));" fullword ascii
    $s15 = "eval(box(\"once%20%3D%20new%20pageYOffset%5B%22Activ%22%20+%20qsa%20+%20%22bject%22%5D%28expanded%20+%20%22l2.X%22%20+%20readyWa" ascii
    $s16 = "safeActiveElement[slow](once[complete]);" fullword ascii
    $s17 = "function then(complete, anim, safeActiveElement, slow) {" fullword ascii
    $s18 = "binary = 1, count = \"Defe\";" fullword ascii
    $s19 = "eval(box(\"transport%20%3D%20returnTrue%3B\"));" fullword ascii
    $s20 = "apply(invert, startTime, xhr, addEventListener);" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}