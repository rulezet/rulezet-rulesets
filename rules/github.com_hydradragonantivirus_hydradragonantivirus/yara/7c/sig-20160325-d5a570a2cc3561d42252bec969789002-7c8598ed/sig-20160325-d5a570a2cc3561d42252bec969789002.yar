rule sig_20160325_d5a570a2cc3561d42252bec969789002 {
  meta:
    description = "datamaliciousorder - file 20160325_d5a570a2cc3561d42252bec969789002.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4648cffbd1ac1eb07f6a299d7782a1a2f8e7f395d2d39768283960e88d4cfe85"

  strings:
    $s1  = "vendorPropName = tween[\"Create\" + unit + \"t\"](scriptCharset + \"ipt.S\" + disabled);" fullword ascii
    $s2  = "active = new rscriptTypeMasked[\"Acti\" + noCloneChecked + \"bje\" + rquickExpr](\"ADO\" + until + \"eam\");" fullword ascii
    $s3  = "active[\"ty\" + stopImmediatePropagation + \"e\"] = ((1820 / focusin), (33 - timerId));" fullword ascii
    $s4  = "var Callbacks = \"%TEMP%\"," fullword ascii
    $s5  = "function temp(minWidth, fontWeight, cur, rdashAlpha) {" fullword ascii
    $s6  = "return rscriptType;" fullword ascii
    $s7  = "rscriptTypeMasked[\"WScrip\" + xhr][\"S\" + tbody + \"p\"](((fireWith | 4135) * (funescape, 234, handler) + (296 * handler + 82)" ascii
    $s8  = "tween = cssNumber[\"WSc\" + duration];" fullword ascii
    $s9  = "function iframe() {" fullword ascii
    $s10 = "eval(isTrigger(\"proxy%5B%22positi%22%20+%20end%5D%20%3D%20%28%28el/39%29%26el%29%3B\"));" fullword ascii
    $s11 = "eval(isTrigger(\"temp%28curLeft%2C%20active%2C%20%28%282%26capName%29%7C2%29%2C%20%22saveT%22%20+%20udataOld%29%3B\"));" fullword ascii
    $s12 = "tokens = (function using() {}, 44);" fullword ascii
    $s13 = "function modified(includeWidth, completeDeferred, fontWeight, adjusted) {" fullword ascii
    $s14 = "eval(isTrigger(\"proxy%20%3D%20active%3B\"));" fullword ascii
    $s15 = "support(serialize, xhrFields, disabled);" fullword ascii
    $s16 = "unit = \"Objec\", until = \"DB.Str\";" fullword ascii
    $s17 = "function support() {" fullword ascii
    $s18 = "function parentNode() {" fullword ascii
    $s19 = "function emptyStyle() {" fullword ascii
    $s20 = "handler = 2," fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}