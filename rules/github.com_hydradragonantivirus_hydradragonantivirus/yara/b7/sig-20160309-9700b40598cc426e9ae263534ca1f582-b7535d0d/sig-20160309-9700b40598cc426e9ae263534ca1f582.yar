rule sig_20160309_9700b40598cc426e9ae263534ca1f582 {
  meta:
    description = "datamaliciousorder - file 20160309_9700b40598cc426e9ae263534ca1f582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4466b9a86a460c55599bbb54c08d44f010ef824dfd1d9c573ab10affbcc6c9b"

  strings:
    $s1  = "namespaces[clazz + len + host + globalEventContext + num](documentIsHTML, ((3948 / padding), (Math.pow(133, pixelPosition) - 175" ascii
    $s2  = " slow))) - (((15 + unquoted) ^ (14 * defer + 13)) | ((keyHooks ^ 2) * (Math.pow(getAll, 2) - dataTypes) + (6 - matcherOut))))) =" ascii
    $s3  = "lastModified[contents + w + hover][close + rmultiDash](((rejectWith / 13) & (Math.pow(udataOld, 2) - complete)));" fullword ascii
    $s4  = "setter[needsContext](diff, slideDown + reliableMarginLeftVal + handlerQueue + send + document + mouseenter + addToPrefiltersOrTr" ascii
    $s5  = "ansports + statusCode + finalValue + show + returnFalse + dirruns, !(((Math.pow((((0 | unquoted) & (54 - ajaxSettings)) & ((Math" ascii
    $s6  = "eyHooks * (243, nodes, 2))) ^ (((responseHeadersString * 2 + div), (Math.pow(96, pixelPosition) - 9071)), ((uid ^ 13) ^ (unquote" ascii
    $s7  = "^ defer))) - ((5 & (unquoted & 7)) * defer + (42 / padding))) ^ ((((2 + keyHooks) & (1 ^ pixelPosition)) + ((3 + getter) - (30 ^" ascii
    $s8  = "namespaces[clazz + len + host + globalEventContext + num](documentIsHTML, ((3948 / padding), (Math.pow(133, pixelPosition) - 175" ascii
    $s9  = "documentIsHTML = childNodes[DOMParser + dataAttr + getAttribute + readyList + nodeName + width](prop + lang) + createPositionalP" ascii
    $s10 = ".pow(16, pixelPosition) - 235) - pixelPosition * 2 * pixelPosition * 2)), (((relative | 1) + -(keyHooks | 1)) | ((keyHooks & 1) " ascii
    $s11 = "documentIsHTML = childNodes[DOMParser + dataAttr + getAttribute + readyList + nodeName + width](prop + lang) + createPositionalP" ascii
    $s12 = "checkbox = setter[getWindow + compiled + num + factory];" fullword ascii
    $s13 = "= (((2 | (unquoted - 7)) * ((keyHooks | 0) * (keyHooks * 2)) * (((defer / 3) * (keyHooks & 1)) * ((slow) - (1591 / self))) + (((" ascii
    $s14 = "tag[setGlobalEval](documentIsHTML.preventDefault(), ((0 ^ keyHooks) + -(1 + relative)), 0);" fullword ascii
    $s15 = "2 * Data + 1) / finish) * ((1 & keyHooks) | (1 + relative)))) & ((((464 ^ classCache) / (Math.pow(29, pixelPosition) - 802)), (k" ascii
    $s16 = "seudo + name + exports + leadingRelative;" fullword ascii
    $s17 = "jqXHR[emptyStyle + callbackExpect] = (relative | (1 + -keyHooks));" fullword ascii
    $s18 = "prop = \"%TEMP\";" fullword ascii
    $s19 = "lastModified = (((160 / keyHooks), (26 + groups)), (((3 & defer) + (50, rcomma, 197, cached)), this));" fullword ascii
    $s20 = "namespaces = lastModified[createCache + rnative][nodeType + fireGlobals + statusCode + parseOnly + iframe + el](noGlobal + attac" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}