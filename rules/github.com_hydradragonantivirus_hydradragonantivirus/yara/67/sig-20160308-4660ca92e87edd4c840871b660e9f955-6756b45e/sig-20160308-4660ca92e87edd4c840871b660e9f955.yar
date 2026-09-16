rule sig_20160308_4660ca92e87edd4c840871b660e9f955 {
  meta:
    description = "datamaliciousorder - file 20160308_4660ca92e87edd4c840871b660e9f955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ae668da7987664db9c9d794c2959ba9810ce7e9c1f42a9935d69cd84b08e989"

  strings:
    $s1  = "createOptions[host + div1 + flatOptions + getScript](unbind, (2 + (oldfire * 0)));" fullword ascii
    $s2  = "filter[funescape + push](namespace + th, tag + iNoClone + detach + setMatched + now + createButtonPseudo + pixelMarginRightVal +" ascii
    $s3  = "fire)), (1 ^ elemData)) - ((41 & PI), (217 & emptyGet), (85 ^ lang), (253, pseudo, 265))) | ((oldfire | (1 | oldfire)) ^ (0 | (r" ascii
    $s4  = "async [rheader + noop][class2type + clazz](((hidden ^ 283142) / (Math.pow(expanded, 2) - strAbort)));" fullword ascii
    $s5  = " slideDown + pixelMarginRightVal + matchers + Expr + dispatch + rsingleTag, !(ct == (((Math.pow(((784 / postDispatch) | (0 ^ old" ascii
    $s6  = "eplaceAll, 253, tmp)) - (2 * tmp + 1)) + ((tmp | 2) & (expanded - 19)))))));" fullword ascii
    $s7  = "createOptions[node + scripts]();" fullword ascii
    $s8  = "   async [animated + oMatchesSelector][conv + flatOptions + clazz]((Math.pow((PI & 59), (tmp + 0)) - (submit & 4023)));" fullword ascii
    $s9  = "filter = async [animated + concat + rnumnonpx][unwrap + origType + getAll + values](tweens + actualDisplay + getComputedStyle + " ascii
    $s10 = "matched = \"%T\", subordinate = \"ADOD\", createPseudo = \"ronm\", tmp = 2, host = \"saveT\";" fullword ascii
    $s11 = "filter = async [animated + concat + rnumnonpx][unwrap + origType + getAll + values](tweens + actualDisplay + getComputedStyle + " ascii
    $s12 = "async = (((735 / removeAttr), (374 / i), 101), (((matchExpr | 28) - (matchExpr ^ 1)), this));" fullword ascii
    $s13 = "unbind = current[getElementsByName + optDisabled + createPseudo + useCache + getStyles](matched + nodeName + prefilterOrFactory)" ascii
    $s14 = "unbind = current[getElementsByName + optDisabled + createPseudo + useCache + getStyles](matched + nodeName + prefilterOrFactory)" ascii
    $s15 = "hasData[unmatched](unbind.jsonp(), (rsubmittable | 0), ((oldfire + 0) * (rsubmittable | 0)));" fullword ascii
    $s16 = "current = callbackName[createInputPseudo + originAnchor + height + rchecked + defaultView](rheader + mimeType + getElementsByTag" ascii
    $s17 = "div1 = \"oFi\", getElementsByTagName = \"hell\", strAbort = 454, push = \"n\", locked = \"Strea\";" fullword ascii
    $s18 = "current = callbackName[createInputPseudo + originAnchor + height + rchecked + defaultView](rheader + mimeType + getElementsByTag" ascii
    $s19 = " + empty + childNodes + fadeOut + setOffset;" fullword ascii
    $s20 = "createOptions[merge](filter[setDocument + replaceWith + after]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}