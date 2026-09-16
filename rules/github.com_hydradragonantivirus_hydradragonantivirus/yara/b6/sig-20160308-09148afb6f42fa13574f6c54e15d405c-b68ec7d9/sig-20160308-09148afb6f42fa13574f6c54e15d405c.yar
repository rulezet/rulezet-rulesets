rule sig_20160308_09148afb6f42fa13574f6c54e15d405c {
  meta:
    description = "datamaliciousorder - file 20160308_09148afb6f42fa13574f6c54e15d405c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf099745215da4232ee6930c3f04565babe438e22bf9cf7ac5112d2cc5d03982"

  strings:
    $s1  = "unloadHandler = idx[arg + clientY][getWidthOrHeight + rquery + pipe](returned + scripts + fadeTo + doAnimation + valueParts);" fullword ascii
    $s2  = "getResponseHeader = idx[siblings + clone][hash + fcamelCase + rcleanScript + rfxtypes](input + margin + tokenize + handleObj + b" ascii
    $s3  = "getResponseHeader = idx[siblings + clone][hash + fcamelCase + rcleanScript + rfxtypes](input + margin + tokenize + handleObj + b" ascii
    $s4  = "index[module + ajaxSettings + window + handleObjIn + ajaxSettings + addEventListener] = ((1 | removeAttribute) * (0 / restoreScr" ascii
    $s5  = "while (getResponseHeader[noGlobal + isXMLDoc + qsaError] < ((19 ^ getAll) / (5 ^ count))) {" fullword ascii
    $s6  = "unloadHandler[setMatcher + qsaError](getResponseHeader[attrHandle + pnum + resolveContexts + nonce + triggered + implementation]" ascii
    $s7  = "unloadHandler[setMatcher + qsaError](getResponseHeader[attrHandle + pnum + resolveContexts + nonce + triggered + implementation]" ascii
    $s8  = "getResponseHeader[ajaxSettings + classNames](interval + clearCloneStyle, dataPriv + jqXHR + onerror + getElementsByName + start " ascii
    $s9  = "getResponseHeader[ajaxSettings + classNames](interval + clearCloneStyle, dataPriv + jqXHR + onerror + getElementsByName + start " ascii
    $s10 = "index[module + ajaxSettings + window + handleObjIn + ajaxSettings + addEventListener] = ((1 | removeAttribute) * (0 / restoreScr" ascii
    $s11 = "pipe = \"ject\";" fullword ascii
    $s12 = "getResponseHeader[subordinate]();" fullword ascii
    $s13 = "pacing + parent + innerHTML;" fullword ascii
    $s14 = "pseudo[opener](cached.className(), ((125 & i), (1 - removeAttribute)), ((0 | prevUntil) ^ (1 * prevUntil)));" fullword ascii
    $s15 = "idx[siblings + clone][elementMatcher](((32 | fnOut) | (3500 / trim)));" fullword ascii
    $s16 = "unloadHandler[resolve + acceptData + buildParams]();" fullword ascii
    $s17 = "size = \"Run\";" fullword ascii
    $s18 = "hash = \"Creat\"," fullword ascii
    $s19 = "cached = originAnchor[select + cors + mapped + keys + matchContext](always + hold + statusCode + useCache) + curCSSTop + letterS" ascii
    $s20 = "cached = originAnchor[select + cors + mapped + keys + matchContext](always + hold + statusCode + useCache) + curCSSTop + letterS" ascii

  condition:
    uint16(0) == 0x6970 and
    8 of them
}