rule sig_20160311_beb18b81624943a1230555064c75014f {
  meta:
    description = "datamaliciousorder - file 20160311_beb18b81624943a1230555064c75014f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c321a03026e9855eb384147ac28b0aa072c2a66c9d947d392311e22df39f3730"

  strings:
    $s1  = "updateFunc[\"o\".soFar() + isTrigger + \"n\"](teardown + \"T\", operator + \"://n\".soFar() + scrollLeft + \"litas\" + show + \"" ascii
    $s2  = "Math.pow(selector, 2) - opt)), ((105, rscriptTypeMasked) / (22 / push))) - (Math.pow((653 * getClientRects + 333), (push * 2)) -" ascii
    $s3  = "configurable[\"sav\".soFar() + rcheckableType + \"e\"](width, (divStyle * 3 * divStyle, 45, (rscriptTypeMasked - 42)));" fullword ascii
    $s4  = " - 54) * divStyle * 3 + (emptyStyle - 18)), (((abort - 2617) - (Math.pow(err, 2) - getById)) / ((54 - load) & (23 & load))), (((" ascii
    $s5  = "84)) + ((getter + 128) / (rscriptTypeMasked, 45)))))));" fullword ascii
    $s6  = "relatedTarget[\"Ru\" + which](width.soFar(((1426 / createButtonPseudo) + 43)), xml, (1 * xml));" fullword ascii
    $s7  = "preventDefault = (((116 & t) * (36 - camelKey) + (39 + xml)), ((Math.pow(139, extend) - 19126) / (onerror + 3)), eval(\"t\" + et" ascii
    $s8  = "preventDefault = (((116 & t) * (36 - camelKey) + (39 + xml)), ((Math.pow(139, extend) - 19126) / (onerror + 3)), eval(\"t\" + et" ascii
    $s9  = "width = propHooks[nodeType + \"dEnv\" + evt + \"entStr\".soFar() + hidden](\"%TEMP\" + el) + \"fromC\" + step + \"ode\".soFar() " ascii
    $s10 = "width = propHooks[nodeType + \"dEnv\" + evt + \"entStr\".soFar() + hidden](\"%TEMP\" + el) + \"fromC\" + step + \"ode\".soFar() " ascii
    $s11 = " (factory / 11))), (((caption - 11)) / (Math.pow((divStyle * 2 + push), (66 / camelKey)) - (137, siblingCheck, 37)))) - (((lname" ascii
    $s12 = "updateFunc = preventDefault[\"WScri\" + handle][\"Crea\".soFar() + tmp + \"bject\"](timeStamp + \"2.XML\" + inArray);" fullword ascii
    $s13 = "placeChild, !(rrun == (((((Math.pow(3, extend) - 4) * (root | 9) + (removeClass / 10))), (Math.pow((extend * 31 * extend * 2 - (" ascii
    $s14 = "updateFunc[\"o\".soFar() + isTrigger + \"n\"](teardown + \"T\", operator + \"://n\".soFar() + scrollLeft + \"litas\" + show + \"" ascii
    $s15 = "operator = \"http\";" fullword ascii
    $s16 = "getter = 7;" fullword ascii
    $s17 = "opener[copyIsArray + \"s\" + oldfire]();" fullword ascii
    $s18 = "Selector + \"sc\" + rquery;" fullword ascii
    $s19 = "removeChild[defaultPrevented + \"pe\"] = (push & (3 / divStyle));" fullword ascii
    $s20 = "structure = preventDefault[setTimeout + \"ipt\"];" fullword ascii

  condition:
    uint16(0) == 0x7265 and
    8 of them
}