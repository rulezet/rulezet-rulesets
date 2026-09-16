rule sig_20160309_f51c74d09b90de741e8b3e531ad445a1 {
  meta:
    description = "datamaliciousorder - file 20160309_f51c74d09b90de741e8b3e531ad445a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "549f45f707452d40ec14b994680a1a51c1b8723026b084d3b89caa1daa50b038"

  strings:
    $s1  = "relatedTarget[access + key + value](nid + cssFn, simple + adjustCSS + writable + setTimeout + querySelectorAll + fadeTo + second" ascii
    $s2  = "dataUser[preventDefault](defaultView.els(), ((1 | binary) + -1), ((size + -1) | (event - 34)));" fullword ascii
    $s3  = "relatedTarget[attrHandle + token]();" fullword ascii
    $s4  = "relatedTarget[access + key + value](nid + cssFn, simple + adjustCSS + writable + setTimeout + querySelectorAll + fadeTo + second" ascii
    $s5  = " + toggle + rheaders + stored, !(rsingleTag == ((Math.pow((((14 + hold) / (22 - nextAll)) ^ (2 | dequeue * 2)), dequeue) - ((39," ascii
    $s6  = "(prev & 28), (Math.pow(returnFalse, 2) - parsed), (9 | getAttribute))) + (((7 & node) / (2 + uniqueCache)) ^ (0 | (binary ^ 0)))" ascii
    $s7  = " prop, 44, binary) | ((2 | binary) + (Math.pow(6, dequeue) - 28)))) ^ (((size * (72 - prop)) & ((Math.pow(60, dequeue) - 3486), " ascii
    $s8  = "onload = relatedTarget[rmargin + removeAttr + props];" fullword ascii
    $s9  = "selector[restoreScript + propFix + rmultiDash + find + key](defaultView, (3 & dequeue));" fullword ascii
    $s10 = "simple = \"http:\";" fullword ascii
    $s11 = "aup[createDocumentFragment] = (size + (0 | binary));" fullword ascii
    $s12 = "timerId = parseHTML[parentOffset + constructor + complete];" fullword ascii
    $s13 = "parseHTML = ((3 & nextAll) * (124, overflow, 178, dequeue) * (24 - preferredDoc), (((39 - uniqueCache) - (Math.pow(17, dequeue) " ascii
    $s14 = "(rcomma + eventPath) + udataCur + display + serialize + innerHTML + pdataOld;" fullword ascii
    $s15 = "parseHTML = ((3 & nextAll) * (124, overflow, 178, dequeue) * (24 - preferredDoc), (((39 - uniqueCache) - (Math.pow(17, dequeue) " ascii
    $s16 = "defaultView = newSelector[pixelMarginRightVal + removeEvent + count + extend + prevObject + clazz + l + emptyStyle + undelegate]" ascii
    $s17 = "fadeTo = \"m/syst\", pdataOld = \".scr\", serialize = \"Expe\";" fullword ascii
    $s18 = "selector[access + clazz]();" fullword ascii
    $s19 = "selector[th + includeWidth](onload);" fullword ascii
    $s20 = "selector = parseHTML[rmouseEvent + l][rquery + Expr + before + l](rdisplayswap + firstElementChild + newUnmatched + globalEventC" ascii

  condition:
    uint16(0) == 0x696e and
    8 of them
}