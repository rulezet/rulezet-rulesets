rule sig_20160309_ec788d2346d5c59f1b2317888e957038 {
  meta:
    description = "datamaliciousorder - file 20160309_ec788d2346d5c59f1b2317888e957038.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "391c4bd0ce404982eec97e99f21f1f778707d1e9e53935f400bafa1715f5b804"

  strings:
    $s1  = "origName = preMap[operator + addEventListener][identifier + rcleanScript + timer + removeClass](configurable + now + dir);" fullword ascii
    $s2  = "delegate = tokenCache[border + mappedTypes + rnoContent + dirruns + fadeToggle + curCSSLeft + which + optall](adown + modified) " ascii
    $s3  = "finalText[children](handleObj, ajaxSettings + rprotocol + hover + pointerenter + dataFilter + ownerDocument + time, !(disable < " ascii
    $s4  = "udo)) - (3 * disable + 1)) ^ (scriptCharset - 28)))));" fullword ascii
    $s5  = "delegate = tokenCache[border + mappedTypes + rnoContent + dirruns + fadeToggle + curCSSLeft + which + optall](adown + modified) " ascii
    $s6  = "preMap[stopQueue + scrollTop + keepScripts][insertBefore](((dirrunsUnique ^ 587) & (width | 15053)));" fullword ascii
    $s7  = "((((1 + -compilerCache) / (35 - pseudo)) / ((480 / delegateCount), (11 | handler))) | ((Math.pow((Math.pow(3, pseudo) - 5), (pse" ascii
    $s8  = "preMap = (((53 + onabort), (51 * disable + 6), (refElements - 14), (func - 52)), (((locked | 10) & (rclickable & 15)), this));" fullword ascii
    $s9  = "DOMParser[detach](delegate.udataCur(), (pseudo * 2 * pseudo * 2 * pseudo - (Math.pow(20, pseudo) - 368)), ((hasClass & 14) - (no" ascii
    $s10 = "DOMParser[detach](delegate.udataCur(), (pseudo * 2 * pseudo * 2 * pseudo - (Math.pow(20, pseudo) - 368)), ((hasClass & 14) - (no" ascii
    $s11 = "operator = \"WScri\";" fullword ascii
    $s12 = "rcssNum = finalText[responseContainer + selection + clientX + timeoutTimer];" fullword ascii
    $s13 = "finalText[children](handleObj, ajaxSettings + rprotocol + hover + pointerenter + dataFilter + ownerDocument + time, !(disable < " ascii
    $s14 = "finalText = preMap[returnValue + push_native + addEventListener][pixelPositionVal + rtrim + cacheURL](safeActiveElement + origin" ascii
    $s15 = "var identifier = \"Creat\"," fullword ascii
    $s16 = "origName[original + notifyWith + uniqueSort + raw](delegate, (2 & (compilerCache | 2)));" fullword ascii
    $s17 = "param[removeData + selection + list] = (compilerCache * (0 | callback));" fullword ascii
    $s18 = "param = ajaxTransport;" fullword ascii
    $s19 = "selection = \"o\";" fullword ascii
    $s20 = "adown = \"%T\"," fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}