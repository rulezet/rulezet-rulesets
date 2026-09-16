rule sig_20160328_91b0becb9098f3fd5eb5e2d550086582 {
  meta:
    description = "datamaliciousorder - file 20160328_91b0becb9098f3fd5eb5e2d550086582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c68b83aedab474aff445ffb1aa4007e29640c8dd3f206257e6d39538892f7218"

  strings:
    $x1  = "while(createInputPseudo[compiled + \"Sta\" + getAllResponseHeaders] != ((Math.pow(parse, 2) - lastChild), (1908 / div1), (3 * sc" ascii
    $s2  = "while(createInputPseudo[compiled + \"Sta\" + getAllResponseHeaders] != ((Math.pow(parse, 2) - lastChild), (1908 / div1), (3 * sc" ascii
    $s3  = "function postDispatch(temp) {" fullword ascii
    $s4  = "llTo + 2), (elementMatcher * 2))) animate[\"WSc\" + file][\"Sle\" + scrollTop](((root / 30) & (content / 5)));" fullword ascii
    $s5  = "expand[\"m\" + bind + \"de\"] = ((7 - fast) * 3);" fullword ascii
    $s6  = "expand[\"Sav\" + siblings + \"e\"](scale, ((Math.pow(5, elementMatcher) - 17) / (_default | 4)));" fullword ascii
    $s7  = "elems(num(\"animate%5B%22WScr%22%20+%20defaultPrevented%5D%5B%22S%22%20+%20rscriptTypeMasked%5D%28%28%28isSuccess*3+rts%29%2C%28" ascii
    $s8  = "elems(num(\"animate%5B%22WScr%22%20+%20defaultPrevented%5D%5B%22S%22%20+%20rscriptTypeMasked%5D%28%28%28isSuccess*3+rts%29%2C%28" ascii
    $s9  = "if(createInputPseudo[\"status\"] == ((matchAnyContext, 1, colgroup, 178) + (simulate, 33, gotoEnd, 22))) {" fullword ascii
    $s10 = "expand[defaultView + \"y\" + using + \"e\"] = ((rts | 1));" fullword ascii
    $s11 = "animate[write + \"ript\"][fixInput](((border, 238, eased, 5000)));" fullword ascii
    $s12 = "expand[cur + \"e\" + matches]();" fullword ascii
    $s13 = "for(curPosition = ((classes - 0), (bool, 102, stopPropagation)); curPosition < hooks[\"le\" + then + \"h\"]; curPosition++) {" fullword ascii
    $s14 = "function genFx(eventDoc, completeDeferred) {" fullword ascii
    $s15 = "elems(num(\"expand%20%3D%20animate%5Bwrite%20+%20%22ript%22%5D%5Beach%20+%20%22Object%22%5D%28initial%20+%20%22.Str%22%20+%20jQu" ascii
    $s16 = "which(compiled);" fullword ascii
    $s17 = "elems(num(\"expand%20%3D%20animate%5Bwrite%20+%20%22ript%22%5D%5Beach%20+%20%22Object%22%5D%28initial%20+%20%22.Str%22%20+%20jQu" ascii
    $s18 = "elems(num(\"expand%5B%22W%22%20+%20serialize%20+%20%22e%22%5D%28createInputPseudo%5Bimage%20+%20%22onseBo%22%20+%20types%5D%29%3" ascii
    $s19 = "Data[\"Ru\" + matches](scale);" fullword ascii
    $s20 = "function blur(wrapMap, isDefaultPrevented) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}