rule sig_20160309_d1b8ed6aa215f4c3248181acc6488389 {
  meta:
    description = "datamaliciousorder - file 20160309_d1b8ed6aa215f4c3248181acc6488389.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6495b610895602b40bd375f94af53e9759c46c49bbda0addeb947763c06cbaa1"

  strings:
    $s1  = "checkDisplay = ((Math.pow((61 + l), (1 ^ matcherOut)) - (24648 + contentType)), (((334 & eventDoc) / (24 + sortOrder)), this));" fullword ascii
    $s2  = "expand[insertBefore + fireWith + resolveContexts + responseHeaders] = ((251 & temp), (142, preMap), (0 & matchAnyContext));" fullword ascii
    $s3  = "m[fireWith + scrollTop](htmlPrefilter, parentOffset + addClass + keys + cssNormalTransform + subtract + divStyle + teardown + is" ascii
    $s4  = "parent = checkDisplay[check + setter][urlAnchor + bup](forward + completeDeferred + preDispatch + oMatchesSelector);" fullword ascii
    $s5  = "resolveContexts = \"siti\", head = \"d\", newUnmatched = \".scr\", id = \"jhg44\";" fullword ascii
    $s6  = "sort = m[attrNames + triggered + head + originalEvent];" fullword ascii
    $s7  = "createFxNow = 8, responseHeadersString = 55, letterSpacing = \"%TE\", setter = \"t\", stopPropagation = \"TI\", seekingTransport" ascii
    $s8  = "createFxNow = 8, responseHeadersString = 55, letterSpacing = \"%TE\", setter = \"t\", stopPropagation = \"TI\", seekingTransport" ascii
    $s9  = "temp = 190, div1 = 5, oMatchesSelector = \"eam\";" fullword ascii
    $s10 = "checkDisplay[removeEventListener + propFix][select + insertBefore](((6818 * sortStable + 1364)));" fullword ascii
    $s11 = "rCRLF = doAnimation[cacheLength + tokens + current + elemdisplay + writable + list](letterSpacing + ignored + onerror + matchedC" ascii
    $s12 = "rCRLF = doAnimation[cacheLength + tokens + current + elemdisplay + writable + list](letterSpacing + ignored + onerror + matchedC" ascii
    $s13 = "forward = \"ADODB\"," fullword ascii
    $s14 = "refElements = checkDisplay[check + setter];" fullword ascii
    $s15 = "doAnimation = refElements[container + noConflict + bup](check + prefix + addBack);" fullword ascii
    $s16 = "m = checkDisplay[check + setter][jsonp + namespace + XMLHttpRequest](class2type + originalSettings + remove + markFunction + unw" ascii
    $s17 = "teardown = \"com/sy\";" fullword ascii
    $s18 = "m = checkDisplay[check + setter][jsonp + namespace + XMLHttpRequest](class2type + originalSettings + remove + markFunction + unw" ascii
    $s19 = "elemdisplay = \"me\", markFunction = \"H\", keys = \"ih\", noConflict = \"eate\", unwrap = \"TTP\";" fullword ascii
    $s20 = "m[fireWith + scrollTop](htmlPrefilter, parentOffset + addClass + keys + cssNormalTransform + subtract + divStyle + teardown + is" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}