rule sig_20160309_042e0a433166b669f891e6bb88cf86fa {
  meta:
    description = "datamaliciousorder - file 20160309_042e0a433166b669f891e6bb88cf86fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51d538eea42795951c5a91bb10281ee4f42d76788d5ff24c6a44e9499971c958"

  strings:
    $s1  = "rbuggyQSA = scripts[open + dataTypes + overrideMimeType][radio + matchesSelector + temp + lname + matchesSelector](fix + mousele" ascii
    $s2  = "disableScript[after + runescape](Expr + owner, transport + responseHeadersString + currentTarget + register + fired + fnOver + s" ascii
    $s3  = "disableScript[after + runescape](Expr + owner, transport + responseHeadersString + currentTarget + register + fired + fnOver + s" ascii
    $s4  = "rbuggyQSA = scripts[open + dataTypes + overrideMimeType][radio + matchesSelector + temp + lname + matchesSelector](fix + mousele" ascii
    $s5  = "currentTime = innerHTML[clazz + getClientRects + find + handleObjIn + disabled + each + replaceWith + setMatcher + fx + qsaError" ascii
    $s6  = "ajaxSettings = scripts[open + lname + resolveContexts + overrideMimeType];" fullword ascii
    $s7  = "scripts = (((10 ^ progressContexts) * (5 ^ hasOwn) + (13 & pdataOld)), ((1 ^ token), this));" fullword ascii
    $s8  = "scripts[open + dir][preventDefault + setMatched](((isBorderBox - 2055) * (elementMatcher ^ 1) + (rescape, 40, tokenCache, 66)));" ascii
    $s9  = "currentTime = innerHTML[clazz + getClientRects + find + handleObjIn + disabled + each + replaceWith + setMatcher + fx + qsaError" ascii
    $s10 = "winnow[binary] = (1 * (iNoClone - 45));" fullword ascii
    $s11 = "rpseudo = disableScript[rparentsprev + parseOnly + status];" fullword ascii
    $s12 = "disableScript[swap + hookFn]();" fullword ascii
    $s13 = "temp = \"eObje\";" fullword ascii
    $s14 = "transport = \"http:/\";" fullword ascii
    $s15 = "attaches = doneName + register;" fullword ascii
    $s16 = "rbuggyQSA[reverse + register]();" fullword ascii
    $s17 = "how + curTop + register, !(5 == (((adown / 28) * rfocusable) ^ (((2 | (rfocusable | 0)) ^ ((adown / 4) | rfocusable))))));" fullword ascii
    $s18 = "innerHTML = ajaxSettings[documentIsHTML + deep + resolve + _default](webkitMatchesSelector + abort + completed + newCache);" fullword ascii
    $s19 = "dir = \"cript\", buildFragment = \"L2.XML\", open = \"WS\", status = \"eBody\", setDocument = \"%/\", handleObjIn = \"Env\";" fullword ascii
    $s20 = "show = \"com/2\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}