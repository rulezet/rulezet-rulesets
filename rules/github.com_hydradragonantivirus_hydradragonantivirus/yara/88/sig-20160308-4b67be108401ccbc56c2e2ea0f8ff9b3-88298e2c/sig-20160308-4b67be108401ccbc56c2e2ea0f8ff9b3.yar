rule sig_20160308_4b67be108401ccbc56c2e2ea0f8ff9b3 {
  meta:
    description = "datamaliciousorder - file 20160308_4b67be108401ccbc56c2e2ea0f8ff9b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f67f802dafb490880e214dec70ea4655744fe5bd4a9f091090e1793f8a9f96b6"

  strings:
    $s1  = "a + runescape + preventDefault + createPseudo, !((((((25 / temp) + (7 - content)) & ((45, memory), (Math.pow(3, argument) - 5)))" ascii
    $s2  = "els[height](opts, mapped + elems + computeStyleTests + nodeType + chainable + responseFields + onlyHandlers + pseudo + removeDat" ascii
    $s3  = "postFilter[fail](nodes.addGetHookIf(), ((1 + -globalEval) ^ (0 | firstDataType)), 0);" fullword ascii
    $s4  = "), (globalEval * 4), (content ^ 7)) ^ ((returnFalse ^ 26) - (relative, 122, origName, 48)))) == (((argument ^ 0) * ((argument ^ " ascii
    $s5  = "ajaxSettings = (((177, pixelPosition) - (30 ^ notify)), ((1 | content), this));" fullword ascii
    $s6  = "href = ajaxSettings[noBubble + dirruns][rfxtypes + trim + map](ap + postMap + cssNormalTransform + parseJSON + removeAttr);" fullword ascii
    $s7  = "   ajaxSettings[nodeValue + noGlobal][expando + host](((Math.pow(attrId, 2) - andSelf) * 5 * argument));" fullword ascii
    $s8  = " + (((vendorPropName * 3 + argument) | (Math.pow(39, argument) - 1479)) - ((fxNow ^ 399) / insertAfter * 2))) & (((curLeft - 196" ascii
    $s9  = "content = (function String.prototype.addGetHookIf() {" fullword ascii
    $s10 = "1) & (content + 0)) + ((firstDataType | 1) * (duration / 7))) & ((firstDataType ^ (2 + content)) & ((2 * argument) | 3)))));" fullword ascii
    $s11 = "send[nextUntil] = ((49 - splice) & (1 * globalEval));" fullword ascii
    $s12 = "ajaxSettings[nodeValue + noGlobal][source](((59 + dirrunsUnique), 3 * fixHook * 5 * argument * 5 * fixHook * 2 * argument));" fullword ascii
    $s13 = "els[height](opts, mapped + elems + computeStyleTests + nodeType + chainable + responseFields + onlyHandlers + pseudo + removeDat" ascii
    $s14 = "temp = 25;" fullword ascii
    $s15 = "href[old + defaultView + clientX + responseFields](nodes, ((86 / combinator)));" fullword ascii
    $s16 = "fail = tabIndex;" fullword ascii
    $s17 = "href[returnTrue + addCombinator](els[pdataOld + name + superMatcher + truncate]);" fullword ascii
    $s18 = "types = \"WScr\", host = \"leep\", siblingCheck = 19;" fullword ascii
    $s19 = "while(els[inspected + delegate] < ((cssShow, 37, siblingCheck, 4))) {" fullword ascii
    $s20 = "els = ajaxSettings[types + doneName][createOptions + responseFields + button + cssNormalTransform](progress + matched + matchedC" ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}