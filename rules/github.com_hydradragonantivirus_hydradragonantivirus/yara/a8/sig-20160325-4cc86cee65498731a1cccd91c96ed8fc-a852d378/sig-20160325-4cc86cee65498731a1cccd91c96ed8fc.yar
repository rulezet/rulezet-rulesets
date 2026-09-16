rule sig_20160325_4cc86cee65498731a1cccd91c96ed8fc {
  meta:
    description = "datamaliciousorder - file 20160325_4cc86cee65498731a1cccd91c96ed8fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98315c82d64d46c9d7e6068b5d5711e4f90f2f4de90bd53a4d723867cff308da"

  strings:
    $s1  = "sortStable[\"Sl\" + relative]((115 / e) * (1 * setMatcher) * (Math.pow(3, setMatcher) - 4) * setMatcher * (38 / select) * (Math." ascii
    $s2  = "return dequeue[tokenCache](forward, targets);" fullword ascii
    $s3  = "function andSelf(forward, dequeue, targets, tokenCache) {" fullword ascii
    $s4  = "sortStable[\"Sl\" + relative]((115 / e) * (1 * setMatcher) * (Math.pow(3, setMatcher) - 4) * setMatcher * (38 / select) * (Math." ascii
    $s5  = "originalProperties = rdisplayswap[\"Expand\" + offsetParent + \"onment\" + events + \"ings\"](selector + \"%/\") + textContent +" ascii
    $s6  = "rdisplayswap = sortStable[\"Create\" + elemLang + \"ct\"](detach + \"ript.S\" + getResponseHeader);" fullword ascii
    $s7  = "originalProperties = rdisplayswap[\"Expand\" + offsetParent + \"onment\" + events + \"ings\"](selector + \"%/\") + textContent +" ascii
    $s8  = "attrId[\"WSc\" + removeChild][\"Sleep\"]((setMatcher * 2 * setMatcher * 2 * hash | (785 & unit)));" fullword ascii
    $s9  = "head = \"s\"," fullword ascii
    $s10 = "cssFn[head + \"e\" + classes]();" fullword ascii
    $s11 = "image = new cssText[\"Act\" + seed + \"bje\" + children](\"ADODB\" + tick + \"m\");" fullword ascii
    $s12 = "textContent = \"dirr\", test = \"so\", clientLeft = 33, conditionFn = \"ructor\", currentTime = \"HTT\", errorCallback = \"2.e\"" ascii
    $s13 = "var then = [][\"const\" + conditionFn][\"proto\" + Expr + \"e\"][test + \"rt\"][arr]();" fullword ascii
    $s14 = "image[\"t\" + append + \"pe\"] = ((newSelector * 1) + start);" fullword ascii
    $s15 = "select = 19, jqXHR = \"dy\", hash = 593;" fullword ascii
    $s16 = "function qsaError(rnotwhite) {" fullword ascii
    $s17 = "markFunction = \"om/P\", selector = \"%TEMP\", oldCallbacks = \"posit\", arr = \"apply\", offsetParent = \"Envir\", rattributeQu" ascii
    $s18 = "eval(qsaError(\"winnow%20%3D%20image%3B\"));" fullword ascii
    $s19 = "markFunction = \"om/P\", selector = \"%TEMP\", oldCallbacks = \"posit\", arr = \"apply\", offsetParent = \"Envir\", rattributeQu" ascii
    $s20 = "rnative(hash, removeAttribute, jqXHR, cssNumber);" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}