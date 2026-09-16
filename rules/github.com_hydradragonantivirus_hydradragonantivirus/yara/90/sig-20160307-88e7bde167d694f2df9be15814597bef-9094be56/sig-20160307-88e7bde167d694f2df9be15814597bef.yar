rule sig_20160307_88e7bde167d694f2df9be15814597bef {
  meta:
    description = "datamaliciousorder - file 20160307_88e7bde167d694f2df9be15814597bef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "321576199d5a5c56ee374e9b71cd492f62db7dc3ece1f54b5bae5b6c1c3d0346"

  strings:
    $s1  = "parseFromString = eased[rreturn + getClientRects + guid + pageX + overflowX + hasContent + matcherOut + mappedTypes + parent](fa" ascii
    $s2  = "runescape[elemData + rwhitespace](rbracket + JSON, showHide + handlerQueue + cssProps + dirruns + responseFields + defer + getCo" ascii
    $s3  = "(0 / tabIndex) ^ ((13 * rscriptTypeMasked + 3) - (input, 41, rfocusable))))));" fullword ascii
    $s4  = "runescape = isDefaultPrevented[clientY + nodeNameSelector + unquoted][isWindow + clearQueue + getComputedStyle + handlerQueue](l" ascii
    $s5  = "parseFromString = eased[rreturn + getClientRects + guid + pageX + overflowX + hasContent + matcherOut + mappedTypes + parent](fa" ascii
    $s6  = "support[pseudos](parseFromString.nid(), ((16 ^ stateVal) - (16 | stateVal)), ((1 & stateString) | (0 | stateString)));" fullword ascii
    $s7  = ")))) == (((((elemLang ^ 36) & (check * 3 + tabIndex)), ((4 | firingIndex) | (144 / conditionFn)), ((3 & rscriptTypeMasked) * (20" ascii
    $s8  = "deOut + contexts) + password + checkOn;" fullword ascii
    $s9  = "runescape = isDefaultPrevented[clientY + nodeNameSelector + unquoted][isWindow + clearQueue + getComputedStyle + handlerQueue](l" ascii
    $s10 = "JSON = \"ET\", password = \"after\", clientLeft = \"sp\", isArrayLike = \"HTTP\";" fullword ascii
    $s11 = "isDefaultPrevented = ((Math.pow((28 ^ doAnimation), (2 + stateString)) - (Math.pow(4989, clearInterval) - 24884634)), (((trim / " ascii
    $s12 = "isDefaultPrevented = ((Math.pow((28 ^ doAnimation), (2 + stateString)) - (Math.pow(4989, clearInterval) - 24884634)), (((trim / " ascii
    $s13 = "E), 5 * clearInterval) ^ (241, (wrapMap & 223), (stateString & 1)))) + ((list + 1) & ((rfocusable | 192), (rscriptTypeMasked | 1" ascii
    $s14 = " & caption)), ((13 - idx) ^ (1 | stateString))) * ((3 & rscriptTypeMasked) & ((1 + stateString) + (2 & rscriptTypeMasked)))) + (" ascii
    $s15 = "runescape[elemData + rwhitespace](rbracket + JSON, showHide + handlerQueue + cssProps + dirruns + responseFields + defer + getCo" ascii
    $s16 = "isDefaultPrevented[swing + handlerQueue][setGlobalEval + rfocusMorph]((3 * margin - (106 - addHandle)));" fullword ascii
    $s17 = "etterSpacing + _jQuery + version + progress + isArrayLike);" fullword ascii
    $s18 = "eased = ready[add + percent + insertAfter](clientY + nodeNameSelector + unquoted + access + find);" fullword ascii
    $s19 = "ready = isDefaultPrevented[swing + handlerQueue];" fullword ascii
    $s20 = "find = \"l\", version = \"2.XM\", pop = \"gr34\", tabIndex = 28;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}