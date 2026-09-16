rule sig_20160309_bcfad5b45573ab29247f1ff5eec3b6d2 {
  meta:
    description = "datamaliciousorder - file 20160309_bcfad5b45573ab29247f1ff5eec3b6d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9e3cffd34c2c3e2d4f09d924eb885d9ee50dfe97fd4cfc16e8c1e5343cb0fa4"

  strings:
    $s1  = "timer[curElem](status, current + textContent + rcheckableType + isSuccess + checkbox + props + cssNumber + isSuccess, !(((div1) " ascii
    $s2  = "timer[targets + restoreScript]();" fullword ascii
    $s3  = "matchesSelector = wrapInner[unit + addToPrefiltersOrTransports][remove + operator + abort + css](isDefaultPrevented + border + c" ascii
    $s4  = "dden) - 735) - (Data ^ 5))) == (((((Data ^ 4) / (rcomma | 46)) ^ ((div1) * (Math.pow(6, isHidden) - 26))) * (((Math.pow(cloneCop" ascii
    $s5  = "wrapInner = (((31 ^ token) * (3 ^ defaultValue) + (Math.pow(28, isHidden) - 734)), (((resolveContexts | 80), (firstChild & 6)), " ascii
    $s6  = "timer = wrapInner[optSelected + remaining][realStringObj + processData + scriptCharset](defaultExtra + option + escapedWhitespac" ascii
    $s7  = "match[pseudos + targets]();" fullword ascii
    $s8  = "timer = wrapInner[optSelected + remaining][realStringObj + processData + scriptCharset](defaultExtra + option + escapedWhitespac" ascii
    $s9  = "wrapInner = (((31 ^ token) * (3 ^ defaultValue) + (Math.pow(28, isHidden) - 734)), (((resolveContexts | 80), (firstChild & 6)), " ascii
    $s10 = "addHandle = createOptions[insertBefore + restoreScript + beforeunload + window + lock + isSuccess + ridentifier + isEmptyObject " ascii
    $s11 = "matchesSelector = wrapInner[unit + addToPrefiltersOrTransports][remove + operator + abort + css](isDefaultPrevented + border + c" ascii
    $s12 = "yEvent, 2) - styles) & 5))) - (((fireWith | 7) * (second / 44)) * ((defaultValue / 11) ^ (focus - 12)) + (((Math.pow(isFunction," ascii
    $s13 = "addHandle = createOptions[insertBefore + restoreScript + beforeunload + window + lock + isSuccess + ridentifier + isEmptyObject " ascii
    $s14 = "timer[curElem](status, current + textContent + rcheckableType + isSuccess + checkbox + props + cssNumber + isSuccess, !(((div1) " ascii
    $s15 = "createOptions = hasClass[rtypenamespace + parseXML + rcleanScript](unit + addToPrefiltersOrTransports + dataTypeOrTransport);" fullword ascii
    $s16 = "isSimulated[bind + lock] = ((div1 + 0) | (set, 1));" fullword ascii
    $s17 = "wrapInner[rhash + serialize + className + visible][serialize + t + documentElement](((rnumnonpx + 10010) & (replaceWith - 8045))" ascii
    $s18 = "wrapInner[rhash + serialize + className + visible][serialize + t + documentElement](((rnumnonpx + 10010) & (replaceWith - 8045))" ascii
    $s19 = "matchesSelector[seekingTransport + ontype + lock](innerHTML);" fullword ascii
    $s20 = "unit = \"WScr\", restoreScript = \"nd\", t = \"lee\", realStringObj = \"Creat\";" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}