rule sig_20160307_15a2a61696f7eb0d7388a2a744194864 {
  meta:
    description = "datamaliciousorder - file 20160307_15a2a61696f7eb0d7388a2a744194864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3caf5ba2744ad332e9142d9b05b6e4f1b5b93a97235ff1f410afa274baf2806e"

  strings:
    $s1  = "matcher[removeClass](serializeArray + fromCharCode, onreadystatechange + rheader + restoreScript + module + isFunction + concat " ascii
    $s2  = "while(matcher[elemData + ontype + rhash + indirect] < (Math.pow((1 ^ apply), 2) - (Math.pow(pageY, 2) - bp))) {" fullword ascii
    $s3  = "rts = \"%TEMP%\";" fullword ascii
    $s4  = "  pageXOffset[makeArray + compare](i, ((0 ^ cssText) | (23 - promise)));" fullword ascii
    $s5  = "matcher[removeClass](serializeArray + fromCharCode, onreadystatechange + rheader + restoreScript + module + isFunction + concat " ascii
    $s6  = "oadHandler + 0))) * (((byElement + 104) | apply * 5 * apply) / ((0, nextSibling, 33, preMap) | (71 - matches)))) | (((35 - html)" ascii
    $s7  = " * (1 * apply) * (44 - setAttribute) / ((7 ^ cssText) * (1 * apply) + (138 / setDocument))) * ((1 * unloadHandler) + ((7 & time)" ascii
    $s8  = "onabort[scale + tokens + includeWidth + cacheURL][second](((stopQueue ^ 18296) - (time, 5893)));" fullword ascii
    $s9  = "  onabort[getElementsByTagName + cacheURL][second](((637 + event) / (6 * apply + 5)));" fullword ascii
    $s10 = "attrHandle = onabort[always + check + curTop];" fullword ascii
    $s11 = "i = sibling[status + fn + dispatch + simulate + parseHTML + old + module + _data + parent + animation](rts + prefix) + conv2 + t" ascii
    $s12 = "  pageXOffset[matchAnyContext](matcher[ownerDocument + col + base + timeStamp + fireWith]);" fullword ascii
    $s13 = "onabort = (((186 ^ offsetHeight)), (((4 + apply) + (5 * apply)), this));" fullword ascii
    $s14 = "  pageXOffset[prototype + module]();" fullword ascii
    $s15 = "var compare = \"File\"," fullword ascii
    $s16 = "sibling = attrHandle[inspected + percent + cacheURL + merge + seekingTransport](scale + Symbol + exports);" fullword ascii
    $s17 = "matcher = onabort[reject + Callbacks + check + curTop][accepts + rsubmittable + pointerleave + cacheURL](rdashAlpha + groups + c" ascii
    $s18 = "rhash = \"ysta\", groups = \"XML\", preMap = 18, triggered = \".s\";" fullword ascii
    $s19 = "ollection + cur + runescape + send);" fullword ascii
    $s20 = "binary = doAnimation + createCache;" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}