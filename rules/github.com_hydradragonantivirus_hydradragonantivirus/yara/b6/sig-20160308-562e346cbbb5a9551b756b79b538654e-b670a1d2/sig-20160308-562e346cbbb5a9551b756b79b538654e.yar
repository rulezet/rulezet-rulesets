rule sig_20160308_562e346cbbb5a9551b756b79b538654e {
  meta:
    description = "datamaliciousorder - file 20160308_562e346cbbb5a9551b756b79b538654e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64d94bd06b17c8469d7b3ebe1b3e8fd0100ee879d2ec37dcce297e61a8a6a9c1"

  strings:
    $s1  = "hold[arg](parent.hooks(), ((2 | thead) - (0 ^ compare)), 0);" fullword ascii
    $s2  = "optgroup[ajaxExtend](noGlobal, url + Callbacks + isSuccess + err + onabort + nid + args + rcleanScript + start, !((((((27497 & s" ascii
    $s3  = "fontWeight = getScript[dataType + urlAnchor + dataShow](trim + visible + responseFields + stopPropagation);" fullword ascii
    $s4  = "isArrayLike = (((10 ^ globalEval) - (0 | thead)), (((0 ^ isFunction) & (7 ^ thead)), this));" fullword ascii
    $s5  = "then[matchedCount + postSelector](optgroup[indirect + set + progressContexts + fixHook + readyState]);" fullword ascii
    $s6  = "    isArrayLike[grep + namespaces + Data + uniqueCache][setPositiveNumber](((47 ^ file), (37 + targets), (37 ^ disableScript), (" ascii
    $s7  = "pixelPosition = \"gs\", compare = 2, noGlobal = \"GET\", rhash = \"lose\";" fullword ascii
    $s8  = "while(optgroup[fadeOut + all] < (15 - sort) * (194, compare)) {" fullword ascii
    $s9  = "    isArrayLike[grep + namespaces + Data + uniqueCache][setPositiveNumber](((47 ^ file), (37 + targets), (37 ^ disableScript), (" ascii
    $s10 = " (base / 29))) & (((concat ^ 99) - fxNow * 2) ^ ((teardown & 7) + (compare * 14))))) == onerror));" fullword ascii
    $s11 = "related[rtagName + matchesSelector + shift] = thead;" fullword ascii
    $s12 = "e * 2 + unique) * (99 / vendorPropName) * 5 * (fxNow - 21));" fullword ascii
    $s13 = "election) / (22 + swing)) | ((56 * compare + 48) / (unique + 9))) / (((simulate ^ 171) & (eased / 12)), ((returnFalse * 2 + comp" ascii
    $s14 = "isArrayLike[grep + opt + cssText + uniqueCache][setPositiveNumber]((4 ^ unique) * 2 * (udataOld / 34) * (teardown ^ 0) * (compar" ascii
    $s15 = "then[lock + compiled + toSelector + pseudo](parent, (135, queue, 1, compare));" fullword ascii
    $s16 = "then[opt + rhash]();" fullword ascii
    $s17 = "optgroup[ajaxExtend](noGlobal, url + Callbacks + isSuccess + err + onabort + nid + args + rcleanScript + start, !((((((27497 & s" ascii
    $s18 = "then = isArrayLike[selected + rsingleTag][overflowY + parentOffset + load + getElementById + uniqueCache](conditionFn + hasOwnPr" ascii
    $s19 = "parent = fontWeight[unqueued + callbackContext + getAll + overwritten + prevUntil + childNodes + shift + pixelPosition](resolve " ascii
    $s20 = "parent = fontWeight[unqueued + callbackContext + getAll + overwritten + prevUntil + childNodes + shift + pixelPosition](resolve " ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}