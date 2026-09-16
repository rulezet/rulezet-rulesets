rule sig_20160309_163871ca6c10fb582ab42a7ba4aa1fa4 {
  meta:
    description = "datamaliciousorder - file 20160309_163871ca6c10fb582ab42a7ba4aa1fa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b0cf897fc3d20226616aecc9933252c1f6dbdd681e98289f785c5d5c53a4194"

  strings:
    $s1  = "stopPropagation[source](postFilter.jsonProp(), (th * 3 * th * 19, (curTop * 2 + matchContext), (Math.pow(226, th) - 50843), (opt" ascii
    $s2  = "hasFocus[pixelMarginRight](getWindow, delay + conv2 + origCount + addClass + eventPath + PI + mappedTypes + rneedsContext, !((((" ascii
    $s3  = "& (((0 ^ contentDocument) | ((1 & contentDocument) | (23 - iframe))) | (((1 * th) + (41 - prefix)) * ((12 ^ prev) - (Math.pow(40" ascii
    $s4  = "stopPropagation[source](postFilter.jsonProp(), (th * 3 * th * 19, (curTop * 2 + matchContext), (Math.pow(226, th) - 50843), (opt" ascii
    $s5  = "matches[targets + scale + subordinate](postFilter, (th + (0 ^ contentDocument)));" fullword ascii
    $s6  = "postFilter = tmp[unit + not + rrun + clientX + documentIsHTML + getText + response + status](first + argument) + bind + createPo" ascii
    $s7  = "percent[currentTarget + w + subordinate]();" fullword ascii
    $s8  = "write = tweener[matchedCount + currentTarget + hasOwnProperty + eq];" fullword ascii
    $s9  = "postFilter = tmp[unit + not + rrun + clientX + documentIsHTML + getText + response + status](first + argument) + bind + createPo" ascii
    $s10 = "notifyWith = \"cript\", PI = \"x.com/\", define = \"scr\", rneedsContext = \"n\";" fullword ascii
    $s11 = "tweener = ((1 ^ parentNode) * (133 / contents) * (1 * th), (((3 + setDocument)), this));" fullword ascii
    $s12 = "contentDocument = 0, bind = \"inclu\", traditional = \"Obj\";" fullword ascii
    $s13 = "((127 ^ eased) + (42 * parentNode + 34))) / (((parentNode + 0) | (elems - 6)) | ((height * 4 + which) / (1081 / resolveWith)))) " ascii
    $s14 = "matches = tweener[matchedCount + notifyWith][removeAttr + traditional + a](elementMatchers + arr + dirruns + setOffset);" fullword ascii
    $s15 = "tmp = write[removeAttr + nextUntil + nextAll](tweeners + origCount + pdataOld + rdisplayswap);" fullword ascii
    $s16 = "hasFocus[pixelMarginRight](getWindow, delay + conv2 + origCount + addClass + eventPath + PI + mappedTypes + rneedsContext, !((((" ascii
    $s17 = "contents = 7;" fullword ascii
    $s18 = "subtract = hasFocus[speeds + subordinate + _data + rneedsContext + attrNames + triggered + fix];" fullword ascii
    $s19 = "matches[onlyHandlers + subordinate](subtract);" fullword ascii
    $s20 = "hasFocus[status + replaceAll]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}