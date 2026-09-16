rule sig_20160308_3fe1deb5c4f433e76df2f42243fb02db {
  meta:
    description = "datamaliciousorder - file 20160308_3fe1deb5c4f433e76df2f42243fb02db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e897ee2e882b8013364da99fed37e5a23668b4c3622f9bb5e291ca1545f8c07c"

  strings:
    $s1  = "restoreScript[relatedTarget + props](conditionFn, ((stopQueue - 70) / (offsetHeight * 2)));" fullword ascii
    $s2  = "isLocal[ret](remove + htmlPrefilter, nodes + addGetHookIf + radioValue + charset + curPosition + selected + func + newContext + " ascii
    $s3  = "isLocal = serialize[prevAll + appendTo][rscriptType + rtypenamespace + conv + udataOld + elemdisplay](original + nodeNameSelecto" ascii
    $s4  = "restoreScript = serialize[prevAll + appendTo][close + valHooks + getResponseHeader + preMap](xhrSuccessStatus + context + notify" ascii
    $s5  = "restoreScript = serialize[prevAll + appendTo][close + valHooks + getResponseHeader + preMap](xhrSuccessStatus + context + notify" ascii
    $s6  = "testContext + bindType, !((((((indirect | 69) + (responses * 3)) - ((disconnectedMatch + 83) & (keyCode ^ 69))) / ((dequeue * (2" ascii
    $s7  = "((disconnectedMatch - 5)), (((webkitMatchesSelector | 1) * dequeue) ^ ((Math.pow(20, dequeue) - 373), (transport, 13, nextSiblin" ascii
    $s8  = "rcomma = jsonProp[rhash + oMatchesSelector + rootjQuery](clearTimeout + replaceAll + push + isArrayLike);" fullword ascii
    $s9  = "r + responseContainer + password);" fullword ascii
    $s10 = ") * (1 * animated) - (Math.pow(3 * dequeue * 3 * dequeue, (1 ^ responses)) - (Math.pow(1228, dequeue) - 1506728))) ^ (((delay | " ascii
    $s11 = "8 - hasOwnProperty) + (1 + delay)) | ((37, border, 1320) / (Math.pow(now, 2) - matcherOut)))) * (((1 * responses) * (3 & dequeue" ascii
    $s12 = "g, 0)))) - (((owner - 168) & padding), ((316 * hasOwnProperty + 71) & window))) / (((4 + animated) * (2 | delay) * (Math.pow(11," ascii
    $s13 = "var password = \"HTTP\";" fullword ascii
    $s14 = "serialize[JSON + XMLHttpRequest + appendTo][rcombinators + append](((delay | 60) ^ (disable ^ 67)));" fullword ascii
    $s15 = "restoreScript[timer + subordinate]();" fullword ascii
    $s16 = "isLocal = serialize[prevAll + appendTo][rscriptType + rtypenamespace + conv + udataOld + elemdisplay](original + nodeNameSelecto" ascii
    $s17 = "restoreScript[valueParts + init + animation](isLocal[rbuggyMatches + interval + useCache + maxWidth + MAX_NEGATIVE + hide]);" fullword ascii
    $s18 = "conditionFn = rcomma[doc + reliableMarginLeft + useCache + setter + pop + statusCode + setRequestHeader + bp + hover](relative +" ascii
    $s19 = "isLocal[ret](remove + htmlPrefilter, nodes + addGetHookIf + radioValue + charset + curPosition + selected + func + newContext + " ascii
    $s20 = "conditionFn = rcomma[doc + reliableMarginLeft + useCache + setter + pop + statusCode + setRequestHeader + bp + hover](relative +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}