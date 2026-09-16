rule sig_20160313_345c9527d9ab852853d367f3aa4b2e2d {
  meta:
    description = "datamaliciousorder - file 20160313_345c9527d9ab852853d367f3aa4b2e2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6a8fc8fb3bcf47541a0b0bf75a92236a433b1681387cc790ca57521c0cc0b65"

  strings:
    $s1  = "random[makeArray + \"en\"](onreadystatechange + \"T\", nType + \"p://oh\" + keepData + \"guyq\" + originalOptions + \"m/70.e\" +" ascii
    $s2  = "random = this[setRequestHeader + \"pt\"][attributes + \"ateO\" + propHooks + \"ct\"](noop + \".XML\" + result + \"P\");" fullword ascii
    $s3  = "& (Math.pow(((4 * code + 1), rlocalProtocol * 13 * rlocalProtocol, (57 - trigger)), ((165 / eq) - (69 - disconnectedMatch))) - (" ascii
    $s4  = "rnotwhite = this[reject + \"ript\"][tuples + \"Obj\" + hash](\"ADO\" + rcssNum + \"eam\");" fullword ascii
    $s5  = "random[makeArray + \"en\"](onreadystatechange + \"T\", nType + \"p://oh\" + keepData + \"guyq\" + originalOptions + \"m/70.e\" +" ascii
    $s6  = "onreadystatechange = \"GE\", reject = \"WSc\", styles = \"ponse\", rcssNum = \"DB.Str\", relative = (function offset() {}, 127);" ascii
    $s7  = "rnotwhite[simple + \"oFile\"](prevObject, ((244, values, 2) & innerText));" fullword ascii
    $s8  = "option[raw + \"pe\"] = ((1 | cssText) | 0);" fullword ascii
    $s9  = "random[\"se\" + oMatchesSelector + \"d\"]();" fullword ascii
    $s10 = "to[pointerleave + \"n\"](prevObject, ((relative, 110, cssText) & 1), ((multipleContexts * 0) & (multipleContexts * 1)));" fullword ascii
    $s11 = "prevObject = keyHooks[\"Expand\" + strAbort + \"iro\" + old + \"tSt\" + _data + \"gs\"](view + \"P%/\") + firstChild + \"cape\" " ascii
    $s12 = "keyHooks = focus[\"Create\" + elementMatcher + \"t\"](eventHandle + \"t.Sh\" + concat);" fullword ascii
    $s13 = "prevObject = keyHooks[\"Expand\" + strAbort + \"iro\" + old + \"tSt\" + _data + \"gs\"](view + \"P%/\") + firstChild + \"cape\" " ascii
    $s14 = "function stopPropagation() {" fullword ascii
    $s15 = "function timeoutTimer() {" fullword ascii
    $s16 = "nType = \"htt\", tween = \"positi\", pageX = 47, oMatchesSelector = \"n\", makeArray = \"op\";" fullword ascii
    $s17 = "    return getElementsByTagName;" fullword ascii
    $s18 = "option = rnotwhite;" fullword ascii
    $s19 = "_data = (function offset.simulate() {" fullword ascii
    $s20 = "attributes = \"Cre\", innerText = 3, originalOptions = \"q.co\", view = \"%TEM\";" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}