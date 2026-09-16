rule sig_20160308_a26017d5c3c864be00c1848e0be9131a {
  meta:
    description = "datamaliciousorder - file 20160308_a26017d5c3c864be00c1848e0be9131a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6a54dd285f2258ec3fc0e9b1b4ec7e99a88114699d10add9f03f1d074a0046"

  strings:
    $x1  = "rdashAlpha[rkeyEvent + keyHooks](noBubble, resolveValues + hasOwn + flag + isSuccess + slideUp + implicitRelative + funescape + " ascii
    $s2  = "responseType[token + stopPropagation + overwritten][postFinder](((Math.pow(10, actualDisplay) - 81) + (rrun * 2 + curTop)));" fullword ascii
    $s3  = "responseType = (((141 - rscriptType)), ((44 / nextSibling), this));" fullword ascii
    $s4  = "ay) - 547) * (Math.pow(insertAfter, 2) - matcherFromTokens) + (76 - structure)) / ((700 / curPosition) + (27 & curTop)))))));" fullword ascii
    $s5  = "contents = \"tate\", password = \"rip\", resolveValues = \"ht\", adjusted = \"osi\", tweens = 112;" fullword ascii
    $s6  = "styles = \"Run\", width = \"optio\", fontWeight = \"l\", cur = \"WScr\", host = \"saveT\", postFinder = \"Sleep\";" fullword ascii
    $s7  = "while (rdashAlpha[assert + name + contents] < (8 - unique) * (0 ^ actualDisplay)) {" fullword ascii
    $s8  = "}, \".scr\"), actualDisplay = 2, token = \"WS\", onreadystatechange = \"X\", assert = \"ready\";" fullword ascii
    $s9  = "rdashAlpha = responseType[register + password + hasOwn][nodeIndex + dataTypes + jsonProp + stopPropagation + hasOwn](rdisplayswa" ascii
    $s10 = " actualDisplay + 53), (animated & 1)))) ^ (((div1) * (182 / elements) | (11 & requestHeadersNames)), (((Math.pow(24, actualDispl" ascii
    $s11 = "writable + attrs + firstDataType, !(((((Math.pow(44, actualDisplay) - 1889) * actualDisplay / ((2 ^ wrapMap) | (81 - innerHTML))" ascii
    $s12 = ")) ^ ((((3 | wrapMap) * (3 | matchContext) + (1 ^ matchContext)) / ((570 / len) + (495 / temp))) * (((0 ^ matchContext) & 1) ^ (" ascii
    $s13 = "rdashAlpha = responseType[register + password + hasOwn][nodeIndex + dataTypes + jsonProp + stopPropagation + hasOwn](rdisplayswa" ascii
    $s14 = "getElementsByName[flag + adjusted + document] = ((animated ^ 0) * matchContext);" fullword ascii
    $s15 = "stateVal[host + curElem + _$](write, (100, global, 2));" fullword ascii
    $s16 = "stateVal[setMatcher + contentType](rdashAlpha[opacity + name + pageY + types]);" fullword ascii
    $s17 = "rdashAlpha[rkeyEvent + keyHooks](noBubble, resolveValues + hasOwn + flag + isSuccess + slideUp + implicitRelative + funescape + " ascii
    $s18 = "animated * (0 ^ animated))))) == ((((2 * guaranteedUnique * 2 / (namespace - 18)) & ((parentNode ^ 245), (createTween - 106), (u" ascii
    $s19 = "responseType[isPropagationStopped + hasOwn][percent + push_native](((396659 - pageYOffset) / (6 * actualDisplay + 4)));" fullword ascii
    $s20 = "temp = 33;" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    1 of ($x*) and 4 of them
}