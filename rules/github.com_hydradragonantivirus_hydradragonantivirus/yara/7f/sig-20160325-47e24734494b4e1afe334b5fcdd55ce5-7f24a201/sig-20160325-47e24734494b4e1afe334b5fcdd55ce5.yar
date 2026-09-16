rule sig_20160325_47e24734494b4e1afe334b5fcdd55ce5 {
  meta:
    description = "datamaliciousorder - file 20160325_47e24734494b4e1afe334b5fcdd55ce5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4a879a8bd3a4fcb883ab158cb778e8dcf003f939a92dc81c6bc6bb68aacab26"

  strings:
    $s1  = "rtrim = doc[\"Expa\" + view + \"ronmen\" + onload + \"ngs\"](boolHook + \"%/\") + compareDocumentPosition + \"n\" + whitespace +" ascii
    $s2  = "list[\"WScrip\" + jqXHR][\"Sle\" + delegateType]((4 + style) * (3 & rnotwhite) * (2 & rnotwhite) * (1 * noCloneChecked) * (Math." ascii
    $s3  = "beforeunload(keys, pageY, script, bool);" fullword ascii
    $s4  = "ridentifier = overflowX = list = fail = readyState.fn();" fullword ascii
    $s5  = "preferredDoc[send]((step, 22, preFilter, 5) * (rnotwhite) * (1 + style) * (170, valHooks, 5) * (step & 2) * (wrap - 53) * (noClo" ascii
    $s6  = "preferredDoc[send]((step, 22, preFilter, 5) * (rnotwhite) * (1 + style) * (170, valHooks, 5) * (step & 2) * (wrap - 53) * (noClo" ascii
    $s7  = "3, rnotwhite) - 4) * (noCloneChecked & 7) * (easing, 128, rnotwhite) * (38 - dataPriv));" fullword ascii
    $s8  = "function getComputedStyle() {" fullword ascii
    $s9  = "rtrim = doc[\"Expa\" + view + \"ronmen\" + onload + \"ngs\"](boolHook + \"%/\") + compareDocumentPosition + \"n\" + whitespace +" ascii
    $s10 = "pageYOffset = new fail[\"Act\" + msg + \"Objec\" + jqXHR](\"ADOD\" + bool + \"eam\");" fullword ascii
    $s11 = "list[\"WScrip\" + jqXHR][\"Sle\" + delegateType]((4 + style) * (3 & rnotwhite) * (2 & rnotwhite) * (1 * noCloneChecked) * (Math." ascii
    $s12 = "eval(abort(\"vendorPropName%20%3D%20new%20list%5Bunbind%20+%20%22eXOb%22%20+%20rreturn%5D%28%22Msx%22%20+%20test%20+%20%22LHTTP." ascii
    $s13 = "var pseudo = [][\"const\" + colgroup][\"proto\" + escaped][\"so\" + script][\"a\" + _default + \"ly\"]();" fullword ascii
    $s14 = "stateVal(script);" fullword ascii
    $s15 = "eval(abort(\"vendorPropName%20%3D%20new%20list%5Bunbind%20+%20%22eXOb%22%20+%20rreturn%5D%28%22Msx%22%20+%20test%20+%20%22LHTTP." ascii
    $s16 = "script = \"rt\"," fullword ascii
    $s17 = "stopPropagation[\"c\" + success + \"se\"]();" fullword ascii
    $s18 = "pageYOffset[done + \"p\" + pointerenter] = ((style & 1) | (has, 62, e));" fullword ascii
    $s19 = "eval(abort(\"vendorPropName%5B%22o%22%20+%20getClass%20+%20%22n%22%5D%28sortOrder%20+%20%22E%22%20+%20off%2C%20%22htt%22%20+%20l" ascii
    $s20 = "var hidden = 183," fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}