rule sig_20160311_e93952726572bc5f30c8a98869ffece3 {
  meta:
    description = "datamaliciousorder - file 20160311_e93952726572bc5f30c8a98869ffece3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9526c95a629a35ad3acd87a9b6d4cef76d2d70ec122a4d84673393f4184efcd1"

  strings:
    $s1  = "MAX_NEGATIVE[\"o\".pointerenter() + detach + \"n\"](tuples + \"ET\", toSelector + \"p://nr\".pointerenter() + udataOld + \"ov.sd" ascii
    $s2  = "matcherFromGroupMatchers[getter + \"u\" + tweener](rcleanScript.pointerenter(((statusCode / 26) | (flag + 45))), ((Math.pow(succ" ascii
    $s3  = "matcherFromGroupMatchers[getter + \"u\" + tweener](rcleanScript.pointerenter(((statusCode / 26) | (flag + 45))), ((Math.pow(succ" ascii
    $s4  = "ck, 8) + (delegateTarget - 269))), ((removeClass * 2 * arg + (27 * always + 5)) & ((inspected / 23) + (matchIndexes | 1))), ((Ma" ascii
    $s5  = "th.pow((memory + 28), (removeClass & 3)) - (implementation | 3213)) + ((pos, 131, rscriptTypeMasked) | (39 - iNoClone))), (((63 " ascii
    $s6  = " | (Symbol - 38))) * ((Math.pow(((addHandle * 5 + msMatchesSelector) / (5 + deep)), ((1392 / attrNames), (Math.pow(19, removeCla" ascii
    $s7  = "click[b + \"oFile\"](rcleanScript, ((checkbox - 22), removeClass));" fullword ascii
    $s8  = "MAX_NEGATIVE = DOMParser[valueIsBorderBox + \"ipt\"][attrHooks + \"ateO\".pointerenter() + wrapMap](\"MSXML2\" + what + \"LHT\" " ascii
    $s9  = "MAX_NEGATIVE = DOMParser[valueIsBorderBox + \"ipt\"][attrHooks + \"ateO\".pointerenter() + wrapMap](\"MSXML2\" + what + \"LHT\" " ascii
    $s10 = "pnum[\"t\" + unit + \"e\"] = ((el * 1) + (el + -1));" fullword ascii
    $s11 = "- throws) - (408 / tick)) & ((2 & arg) + (1 | matchIndexes)))) * (((Math.pow(57, removeClass) - 3181) / tick * 2)) == (((el * 0)" ascii
    $s12 = "then = \"Str\", rscriptTypeMasked = 28, tick = 17, isImmediatePropagationStopped = 48, handlers = 96;" fullword ascii
    $s13 = "var getter = \"R\"," fullword ascii
    $s14 = "click[time + \"e\".pointerenter() + tweener]();" fullword ascii
    $s15 = "ss) - 328), (returnFalse + 132), (removeClass & 3))) - ((current - 1200) & elemLang * 3 * elemLang * 13)) - (((el * 1) & (matchI" ascii
    $s16 = "selectedIndex = rbuggyMatches[\"Creat\" + pattern + \"t\"](valueIsBorderBox + \"ipt.\".pointerenter() + attributes + \"ll\");" fullword ascii
    $s17 = "MAX_NEGATIVE[timer + \"nd\".pointerenter()]();" fullword ascii
    $s18 = "MAX_NEGATIVE[\"o\".pointerenter() + detach + \"n\"](tuples + \"ET\", toSelector + \"p://nr\".pointerenter() + udataOld + \"ov.sd" ascii
    $s19 = "rbuggyMatches = DOMParser[\"WSc\".pointerenter() + self];" fullword ascii
    $s20 = "rmsPrefix[input + \"se\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}