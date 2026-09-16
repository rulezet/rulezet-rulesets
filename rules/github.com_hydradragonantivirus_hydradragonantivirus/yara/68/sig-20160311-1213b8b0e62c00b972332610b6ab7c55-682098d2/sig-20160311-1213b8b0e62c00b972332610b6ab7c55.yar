rule sig_20160311_1213b8b0e62c00b972332610b6ab7c55 {
  meta:
    description = "datamaliciousorder - file 20160311_1213b8b0e62c00b972332610b6ab7c55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c4a8b7e9c988f1a0b73ddb35c05093dadcd77fd28ee93ae59bab953181b67b4"

  strings:
    $s1  = "suffix = serializeArray[\"Expa\" + acceptData + \"vironm\".offset() + func + \"Stri\" + head](\"%TEMP%\" + forward) + \"ajaxE\"." ascii
    $s2  = "suffix = serializeArray[\"Expa\" + acceptData + \"vironm\".offset() + func + \"Stri\" + head](\"%TEMP%\" + forward) + \"ajaxE\"." ascii
    $s3  = "now[newDefer + \"e\" + qsa](\"GE\" + simple, \"http:/\".offset() + constructor + \".21\" + superMatcher + \"hdd\" + attributes +" ascii
    $s4  = "trigger[\"R\" + sourceIndex + \"n\".offset()](suffix.offset((Math.pow((hash & 62), (combinator + 0)) - matchesSelector * 5 * the" ascii
    $s5  = " + 10)), ((Math.pow(then, 2) - exports) | (68 | container)), ((8 + tbody) | (Math.pow(20, combinator) - 371))), (((fnOut, 242, r" ascii
    $s6  = "trigger[\"R\" + sourceIndex + \"n\".offset()](suffix.offset((Math.pow((hash & 62), (combinator + 0)) - matchesSelector * 5 * the" ascii
    $s7  = "triggered[\"o\".offset() + getScript + \"n\"]();" fullword ascii
    $s8  = ")) + (0 | container))) - (Math.pow(((2 * boxSizingReliableVal * 3 * vendorPropName * 3 / combinator * 3), ((map - 2629) / (tbody" ascii
    $s9  = " (createTextNode - 7)) + (origType + (171, vendorPropName))))) == (Math.pow(((42 - statusText) | ((Math.pow(37, combinator) - (1" ascii
    $s10 = "ound, 29) + vendorPropName * 3) / ((handleObj * 4 + combinator) | (72 / el)))) - ((Math.pow((472 | dir), (2 / offsetWidth)) - (1" ascii
    $s11 = "define = (((2 + throws) | (14 & opt)), (Math.pow(18, combinator) - 305), eval(\"t\" + show + \"is\".offset()));" fullword ascii
    $s12 = "65, push_native)) / (Math.pow((176 / needsContext), (3 & combinator)) - (9 & param)))), (((1 * combinator) & (3 & vendorPropName" ascii
    $s13 = "triggered[state + \"ToF\" + elementMatchers](suffix, ((expando - 81), (rdisplayswap & 231), (fns, 110, addEventListener, 2)));" fullword ascii
    $s14 = "offset() + curCSS, !(((((documentElement - 44) - ((collection - 13) & (then + 2))) & (((createPseudo / 37) & (combinator * 3 + o" ascii
    $s15 = "ffsetWidth)))) + ((((1127 + jqXHR) / (9 * handleObj)) - ((299 - source) & (6 * dispatch + 2))) / (((prefix, 113, chainable, 1) *" ascii
    $s16 = "triggered = define[\"WScr\" + parseXML][\"Cre\".offset() + fix + \"ect\"](startTime + \"B.S\" + version);" fullword ascii
    $s17 = "now[newDefer + \"e\" + qsa](\"GE\" + simple, \"http:/\".offset() + constructor + \".21\" + superMatcher + \"hdd\" + attributes +" ascii
    $s18 = "now = define[ownerDocument + \"ipt\".offset()][click + \"eObjec\" + nodes](\"MSXML\" + success + \"HTTP\".offset());" fullword ascii
    $s19 = "hookFn = \"Crea\", fns = 229, fnOut = 154, source = 140, chainable = 164, head = \"ngs\";" fullword ascii
    $s20 = " protocol + \".\" + fragment + \"r\";" fullword ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}