rule sig_20160309_27eb0670310c718ce47586cb3b174b45 {
  meta:
    description = "datamaliciousorder - file 20160309_27eb0670310c718ce47586cb3b174b45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8f7da91562cd36d7e59a5c87371fdfed44116142ec8df3d315d394a5c7a4e78"

  strings:
    $x1  = "i[copyIsArray + ifModified](a, slideDown + replaceAll + expando + matcher + p + letterSpacing + version + dir + rxhtmlTag + wrap" ascii
    $s2  = "name = height[interval + push_native][fixHook + responseHeadersString + rkeyEvent + preexisting](createComment + subordinate + d" ascii
    $s3  = "ipulationTarget | 1))) + (Math.pow((((Math.pow(list, 2) - delegateType) & (49, hasOwn, 12, pixelMarginRight)) - (2 * onabort * 2" ascii
    $s4  = "name = height[interval + push_native][fixHook + responseHeadersString + rkeyEvent + preexisting](createComment + subordinate + d" ascii
    $s5  = "setTimeout = until[rcomma + rhash + ifModified + code + container + preexisting + inPage](props + getElementById) + iframe + cre" ascii
    $s6  = "setTimeout = until[rcomma + rhash + ifModified + code + container + preexisting + inPage](props + getElementById) + iframe + cre" ascii
    $s7  = " + globalEval + serialize, !(maxWidth < ((((1 + -global) | (1 * manipulationTarget)) | (((9 * maxWidth + 1) / (src & 41)) + (man" ascii
    $s8  = "matcherOut[margin](setTimeout.keyCode(), ((3 - onabort) + -(35 - siblings)), ((0 & global) ^ (64, detectDuplicates, 106, manipul" ascii
    $s9  = "i = height[postDispatch + relatedTarget + rbrace][getClientRects + ajaxSettings + readyList + always](file + appendTo + backgrou" ascii
    $s10 = "i = height[postDispatch + relatedTarget + rbrace][getClientRects + ajaxSettings + readyList + always](file + appendTo + backgrou" ascii
    $s11 = "props = \"%TE\", relatedTarget = \"S\", version = \"tem/l\", always = \"ct\", rcomma = \"Ex\", backgroundClip = \"X\";" fullword ascii
    $s12 = "hasOwnProperty[reset] = ((1 ^ manipulationTarget) + (0 | manipulationTarget));" fullword ascii
    $s13 = "name[childNodes + resolve + fix + responses](setTimeout, (2 | manipulationTarget));" fullword ascii
    $s14 = " * onabort * 5 - (Math.pow(visible, 2) - progress))), (1 ^ ((onabort ^ 1) & (clone)))) - (((2 + global) & (3 & clone)) + ((38 - " ascii
    $s15 = "wrap = \"f6\", manipulationTarget = 0, clone = 3;" fullword ascii
    $s16 = "height[queue + preexisting][ajaxConvert + responses + cssHooks](((285038 / rscriptType) & (1458 ^ parentsUntil)));" fullword ascii
    $s17 = "uniqueCache = height[postDispatch + relatedTarget + pixelMarginRightVal + removeClass];" fullword ascii
    $s18 = "insertBefore = i[mouseHooks + get + unit + input];" fullword ascii
    $s19 = "ataFilter + booleans + forward);" fullword ascii
    $s20 = "a = \"GET\", rhash = \"pandE\", unit = \"on\";" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}