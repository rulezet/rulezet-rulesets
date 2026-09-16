rule sig_20160309_cd04ab0d613ffce744e84ad452cd3d45 {
  meta:
    description = "datamaliciousorder - file 20160309_cd04ab0d613ffce744e84ad452cd3d45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "220b0745caee2eb6f41a34a6752ea178b69d6148fb3ae56a524090efc0d8244c"

  strings:
    $s1  = "camel[documentElement + rfocusable](interval + params, teardown + host + isLocal + minWidth + isDefaultPrevented + siblingCheck " ascii
    $s2  = "jsonpCallback[string + valueIsBorderBox + manipulationTarget][selectors](((noCloneChecked + 2233) | (Math.pow(b, 2) - winnow)));" ascii
    $s3  = "onreadystatechange[preFilters + pixelMarginRightVal] = ((xhrSupported | 5) - (wrap ^ 34));" fullword ascii
    $s4  = "inspectPrefiltersOrTransports = \"peed\", input = 19, args = \"/logs\", host = \"ttp://\";" fullword ascii
    $s5  = "2 - createPositionalPseudo)) ^ ((5 & token) + 1))))));" fullword ascii
    $s6  = "(1 * classCache)) * ((21 + cssHooks) / (330 / wrap)) * (3 | (classCache | 0)) - (((Math.pow(token, 2) - createHTMLDocument) & (6" ascii
    $s7  = "special = resolveValues[m + duplicates + getAttributeNode + rneedsContext + namespace + prependTo](Data + beforeSend) + prependT" ascii
    $s8  = "namespace = \"ing\", token = 7, rheader = 6, insertBefore = \"MS\";" fullword ascii
    $s9  = "camel[documentElement + rfocusable](interval + params, teardown + host + isLocal + minWidth + isDefaultPrevented + siblingCheck " ascii
    $s10 = "jsonpCallback = (((Math.pow(145, state) - 20879) ^ (submit & 59)), (((t + 32), (input + 3), (ct, 5)), this));" fullword ascii
    $s11 = "support[contexts] = (wrapAll + 0);" fullword ascii
    $s12 = "onreadystatechange = support;" fullword ascii
    $s13 = "camel[readyState + version]();" fullword ascii
    $s14 = "special = resolveValues[m + duplicates + getAttributeNode + rneedsContext + namespace + prependTo](Data + beforeSend) + prependT" ascii
    $s15 = "cache = jsonpCallback[string + list + implementation][timer + value + unit + pixelMarginRight + implementation](createFxNow + se" ascii
    $s16 = "memory = \"com/sy\";" fullword ascii
    $s17 = "+ memory + options + args + selection + matchContext + attaches + addToPrefiltersOrTransports + classNames, !(adjustCSS < ((((1 " ascii
    $s18 = "version = \"nd\";" fullword ascii
    $s19 = "wrap = 15, createFxNow = \"ADODB\", addToPrefiltersOrTransports = \"4g\", curTop = \"Objec\";" fullword ascii
    $s20 = "cache = jsonpCallback[string + list + implementation][timer + value + unit + pixelMarginRight + implementation](createFxNow + se" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}