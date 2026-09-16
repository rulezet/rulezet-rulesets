rule sig_20160308_ba6fa6ac176191b408fc150b2e0fb06e {
  meta:
    description = "datamaliciousorder - file 20160308_ba6fa6ac176191b408fc150b2e0fb06e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29b3f36e43d38c5e420a38124e87acbd5c689e12520caf0ef04c3e33fda5929b"

  strings:
    $s1  = "copyIsArray[then](removeAttr.iframe(), ((1 * createTextNode) * (0 / requestHeaders)), ((Math.pow(8, fragment) - 55) - (orig * 3)" ascii
    $s2  = "copyIsArray[then](removeAttr.iframe(), ((1 * createTextNode) * (0 / requestHeaders)), ((Math.pow(8, fragment) - 55) - (orig * 3)" ascii
    $s3  = "outerCache = firstChild[Deferred + checkbox][maxWidth + run + noGlobal + completeDeferred + emptyGet](empty + proxy + realString" ascii
    $s4  = "outerCache = firstChild[Deferred + checkbox][maxWidth + run + noGlobal + completeDeferred + emptyGet](empty + proxy + realString" ascii
    $s5  = "inspect - 39) + ((createTextNode * 1) * (rcssNum - 53))), ((cssExpand / 41) & (fragment ^ 1))) - (Math.pow(((isBorderBox + 1109)" ascii
    $s6  = "d | 9) ^ (createTextNode | 33)) - ((Math.pow(speeds, 2) - bup) * (9 - checkContext) + (2 + fragment))) * ((1 | (rtrim, 129, even" ascii
    $s7  = "pointerenter = firstChild[tokenCache + dataAttr][maxWidth + minWidth + mappedTypes + originalOptions + isDefaultPrevented + getW" ascii
    $s8  = "idthOrHeight](before + dataUser + view + rootjQuery + pageY);" fullword ascii
    $s9  = "outerCache[expando](mozMatchesSelector, off + raw + htmlPrefilter + unshift + push + fxNow + onload + hasData + defaultPrefilter" ascii
    $s10 = "firstChild = (((11 ^ teardown) * (7 + createTextNode) + (2 + orig)), (((178 * fragment + 106) / (scripts / 6)), this));" fullword ascii
    $s11 = "pointerenter[overflow + postMap]();" fullword ascii
    $s12 = "getElementsByClassName[lock + letter + readyState] = (fragment * 2 * node * 3 * fragment * 2, dataTypeExpression, (48 + offsetPa" ascii
    $s13 = "mapped = leadingRelative[siblingCheck + headers + emptyGet](tokenCache + includeWidth + mappedTypes + finalValue + flag);" fullword ascii
    $s14 = "proxy = \"XML\", postMap = \"lose\", mimeType = \"MP%\", special = \"Sleep\", expando = \"open\";" fullword ascii
    $s15 = "getElementsByClassName[lock + letter + readyState] = (fragment * 2 * node * 3 * fragment * 2, dataTypeExpression, (48 + offsetPa" ascii
    $s16 = " / (letterSpacing + 6)), ((setMatched, 100, dir, 0) ^ (fragment | 2))) - ((defineProperty, 189, split) ^ 1823))) | (((appendChil" ascii
    $s17 = "firstChild[clone + mappedTypes][location + preMap](((179 - propFilter), (Math.pow(13500, fragment) - 182235000)));" fullword ascii
    $s18 = "before = \"AD\", scripts = 198;" fullword ascii
    $s19 = "node = 5, run = \"ateO\", pageYOffset = \"7\", dataUser = \"ODB\";" fullword ascii
    $s20 = "host = \"nd\"," fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}