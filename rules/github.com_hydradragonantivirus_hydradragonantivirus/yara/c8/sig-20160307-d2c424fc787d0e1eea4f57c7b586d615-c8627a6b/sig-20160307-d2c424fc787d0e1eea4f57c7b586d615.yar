rule sig_20160307_d2c424fc787d0e1eea4f57c7b586d615 {
  meta:
    description = "datamaliciousorder - file 20160307_d2c424fc787d0e1eea4f57c7b586d615.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfa61a487d3d68467c66f135265054981a5d679e9447c60f2315d165e216662d"

  strings:
    $s1  = "href[div1 + index](fcamelCase, types + write + animation + tr + focusin + clearQueue + defaultExtra + ret + jsonProp + statusCod" ascii
    $s2  = "e + currentTarget + types + func, !(((((callback * 3) - (prototype - 0)) * (((isLocal ^ 0) & (callback + -1)) | (isLocal | (165," ascii
    $s3  = "stored[inspect + Data + structure][finalDataType + contentType + dest](((MAX_NEGATIVE - 99517) / (parse + 5)));" fullword ascii
    $s4  = "href = stored[off + rmouseEvent + maxWidth][firingIndex + el + target](removeEventListener + removeClass + newCache + push);" fullword ascii
    $s5  = "param = stored[sort + structure][firingIndex + eventHandle + clientY + password + lock + maxWidth](Expr + nodes + propFix);" fullword ascii
    $s6  = " callback)))) ^ (((1 * prototype) & (33 / rmargin)) | (((226 - fast) / (109 - contents)) | ((3 & run) & (3 & run))))) == 2));" fullword ascii
    $s7  = "stored = (((318 - width)), (((Math.pow(7, prototype) - 40) & parse * 2), this));" fullword ascii
    $s8  = "startLength = rdisplayswap[firingIndex + computed + version](delegate + setGlobalEval + progress + parent + slow);" fullword ascii
    $s9  = "matcherIn[elemLang](newContext.onlyHandlers(), ((requestHeaders, 62, cssHooks) - 5 * prototype), (0 & callback));" fullword ascii
    $s10 = "dest = \"ep\", isLocal = 0, target = \"bject\", origName = \"Expand\";" fullword ascii
    $s11 = "param[overflow + maxWidth + iNoClone](href[nativeStatusText + rnative + hasFocus + get]);" fullword ascii
    $s12 = "password = \"bje\"," fullword ascii
    $s13 = "til](multipleContexts + display + crossDomain) + before + params + maxWidth + contextBackup + DOMParser;" fullword ascii
    $s14 = "param[contexts + iNoClone]();" fullword ascii
    $s15 = "rdisplayswap = stored[inspect + Data + structure];" fullword ascii
    $s16 = "href[left + evt]();" fullword ascii
    $s17 = "elemLang = nativeStatusText + unquoted;" fullword ascii
    $s18 = "param[reset + rsubmitterTypes](newContext, (isLocal ^ 2));" fullword ascii
    $s19 = "createDocumentFragment[fadeToggle + maxWidth + argument] = ((isLocal & 1) | (isLocal / 50));" fullword ascii
    $s20 = "version = \"Object\";" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}