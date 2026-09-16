rule sig_20160308_62ea1aa9f4e77c5104961e24ff3ba25d {
  meta:
    description = "datamaliciousorder - file 20160308_62ea1aa9f4e77c5104961e24ff3ba25d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb51f18e9208ed51c4ce05950b28e269f462d11d3f09e89ada2c6919adf633ed"

  strings:
    $s1  = "+ rdashAlpha + ridentifier + MAX_NEGATIVE + complete + textContent + attrId + then, !(genFx < ((((Math.pow(96, getAttributeNode)" ascii
    $s2  = "hasClass[replaceChild + tokens](getClass + eq, requestHeadersNames + nonce + rsingleTag + settings + doScroll + type + adjusted " ascii
    $s3  = "matcherFromGroupMatchers[tokenize + properties + self + finalDataType + prefilterOrFactory][disconnectedMatch + curValue + remov" ascii
    $s4  = "nnow * 2)) - (getAttributeNode * 2)) * (i, 11) / ((((Math.pow(fragment, 2) - rbuggyMatches) | (1 + rsubmittable)) ^ ((153 - reje" ascii
    $s5  = "matcherFromGroupMatchers = ((5 | fnOut), (((Math.pow(13, getAttributeNode) - 151) - (tween / 41)), this));" fullword ascii
    $s6  = ".pow(4, getAttributeNode) - 11) * (winnow * 2));" fullword ascii
    $s7  = " - 9084) / (preFilters | 44)) & ((define / 24) - (duration | 4))) * (Math.pow(((rsubmittable / 2) ^ (getAttributeNode | 1)), (wi" ascii
    $s8  = "ct) - (3 * getAttributeNode + 1))), (((outermostContext + 66) - (opener + 11)) ^ (Math.pow((duration * 7 + getAttributeNode), (3" ascii
    $s9  = "triggerHandler = \"ript\", rmouseEvent = \"%TEMP%\", finalDataType = \"p\", nonce = \"p://la\", aup = \"pen\";" fullword ascii
    $s10 = "hasClass = matcherFromGroupMatchers[tokenize + oldfire + mouseHooks][responseHeaders + hide + completed + Data](scrollLeft + rid" ascii
    $s11 = "hasClass = matcherFromGroupMatchers[tokenize + oldfire + mouseHooks][responseHeaders + hide + completed + Data](scrollLeft + rid" ascii
    $s12 = "eChild]((sibling | 5) * (getAttributeNode + 3) * getAttributeNode * (4 ^ winnow) * (2 ^ winnow) * (1 * getAttributeNode) * (Math" ascii
    $s13 = "hasClass[replaceChild + tokens](getClass + eq, requestHeadersNames + nonce + rsingleTag + settings + doScroll + type + adjusted " ascii
    $s14 = "disable[cloneCopyEvent + realStringObj + fixHooks + self + curValue](rtrim, (teardown - 44));" fullword ascii
    $s15 = "matcherFromGroupMatchers[b + args][propFilter](((rfxtypes, 186, always, 207) - (ct & 123)));" fullword ascii
    $s16 = "offsetParent = \"dEnvi\", adjusted = \"kri.\", outermostContext = 10, reject = 98, setPositiveNumber = \".Str\", e = \".scr\";" fullword ascii
    $s17 = "disable = matcherFromGroupMatchers[tokenize + active + triggerHandler][cssText + pushStack + dispatch + original](ret + setPosit" ascii
    $s18 = "disable = matcherFromGroupMatchers[tokenize + active + triggerHandler][cssText + pushStack + dispatch + original](ret + setPosit" ascii
    $s19 = "matcherFromGroupMatchers[tokenize + properties + self + finalDataType + prefilterOrFactory][disconnectedMatch + curValue + remov" ascii
    $s20 = "realStringObj = \"veT\", doneName = \"nseBod\", dequeue = \"ready\", keepScripts = 20, original = \"ct\";" fullword ascii

  condition:
    uint16(0) == 0x2069 and
    8 of them
}