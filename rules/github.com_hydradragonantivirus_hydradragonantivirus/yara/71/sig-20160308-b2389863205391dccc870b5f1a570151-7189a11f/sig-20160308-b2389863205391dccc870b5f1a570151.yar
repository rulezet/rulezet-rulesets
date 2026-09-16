rule sig_20160308_b2389863205391dccc870b5f1a570151 {
  meta:
    description = "datamaliciousorder - file 20160308_b2389863205391dccc870b5f1a570151.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ed7a9fbb2ed1a1e60eaa7f609662fccf39689dd679e6e57d7194e80a06d53fd"

  strings:
    $s1  = "specified[rtypenamespace](bind, prevUntil + serialize + classes + rheader + _evalUrl + base + getJSON, !((((((41 + define) - (41" ascii
    $s2  = "prevObject = s[rnotwhite + a + noConflict + disableScript][nodeName + curCSSLeft + password](extra + compile + current + filters" ascii
    $s3  = "prevObject = s[rnotwhite + a + noConflict + disableScript][nodeName + curCSSLeft + password](extra + compile + current + filters" ascii
    $s4  = "s[animation + disableScript][isHidden + parseOnly]((97 ^ (Math.pow(pattern, 2) - pdataCur)));" fullword ascii
    $s5  = "while(specified[dataUser + rCRLF + newDefer + forward] < ((dir ^ 0) ^ (Math.pow(rclass, 2) - createTween))) {" fullword ascii
    $s6  = "pipe[createButtonPseudo + originalProperties] = ((1 + rdisplayswap) + -1);" fullword ascii
    $s7  = "elems = returned[random + tmp + rpseudo + overflowY + detectDuplicates + end](noop + tmp + target + handleObjIn) + contains + ou" ascii
    $s8  = "elems = returned[random + tmp + rpseudo + overflowY + detectDuplicates + end](noop + tmp + target + handleObjIn) + contains + ou" ascii
    $s9  = "w(178, dir) - 31469), (host - 11)) | ((rdisplayswap | 0) | rdisplayswap)))) > 5));" fullword ascii
    $s10 = "specified[rtypenamespace](bind, prevUntil + serialize + classes + rheader + _evalUrl + base + getJSON, !((((((41 + define) - (41" ascii
    $s11 = "define = 8, end = \"ings\", noConflict = \"p\", compareDocumentPosition = \"send\", password = \"ect\";" fullword ascii
    $s12 = "returned = sort[nodeName + mimeType + rneedsContext + disableScript](animation + innerHTML + i);" fullword ascii
    $s13 = "s[animation + disableScript][off](((9031 + els)));" fullword ascii
    $s14 = "target = \"MP\"," fullword ascii
    $s15 = "checkOn = 115, unbind = \"eate\", detectDuplicates = \"Str\", host = 11, dataUser = \"read\", firing = 140;" fullword ascii
    $s16 = "s = (((3422 / nType), (20 ^ copyIsArray)), (((5 ^ manipulationTarget) & (25 + rclass)), this));" fullword ascii
    $s17 = "var bind = \"GET\"," fullword ascii
    $s18 = "specified = s[rnotwhite + isHidden + tweener][guid + unbind + globalEventContext](finalText + serializeArray + needsContext);" fullword ascii
    $s19 = "prevObject[related + rprotocol + keys](elems, (firing, 2));" fullword ascii
    $s20 = "sort = s[calculatePosition + parseJSON + noConflict + disableScript];" fullword ascii

  condition:
    uint16(0) == 0x546e and
    8 of them
}