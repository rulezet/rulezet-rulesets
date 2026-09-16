rule sig_20160307_8263985f3567b8fc9b22f727135acdda {
  meta:
    description = "datamaliciousorder - file 20160307_8263985f3567b8fc9b22f727135acdda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1304a541da3179ab6e4635c95bd1eb916e1fa94b4dc0202dd9a1b5466092c077"

  strings:
    $s1  = "parseFromString[newUnmatched](actualDisplay + t, hasFocus + reverse + readyList + num + unmatched + rchecked + _jQuery, !((((((3" ascii
    $s2  = "base[currentTarget](parseFromString[bindType + thead + focus]);" fullword ascii
    $s3  = "base[resolveContexts + chainable + speed + chainable](cssNumber, ((Math.pow(curLeft, 2) - overflowY), (210, overrideMimeType, 21" ascii
    $s4  = "isDefaultPrevented = 24, hasFocus = \"http:\", show = \".scr\", random = 3, actualDisplay = \"GE\";" fullword ascii
    $s5  = "((1 * multipleContexts) & (1 + multipleContexts))) - ((32 - amd) + (2 & random)))) + (((1 ^ rtagName) * 1) + -(((postFinder + 4)" ascii
    $s6  = "origFn[remaining + tokens][Deferred](((750 / getAttribute) + (25 & boxSizingReliable)));" fullword ascii
    $s7  = "base[resolveContexts + chainable + speed + chainable](cssNumber, ((Math.pow(curLeft, 2) - overflowY), (210, overrideMimeType, 21" ascii
    $s8  = "cssNumber = compare[token + div + getClientRects + createCache + rattributeQuotes + rejectWith](fnOver + rwhitespace) + which + " ascii
    $s9  = "while(parseFromString[removeAttribute + matchers + tokens + input + chainable] < ((13 / cssHooks) * (28 - isDefaultPrevented))) " ascii
    $s10 = "while(parseFromString[removeAttribute + matchers + tokens + input + chainable] < ((13 / cssHooks) * (28 - isDefaultPrevented))) " ascii
    $s11 = "origFn[remaining + tokens][curElem + finalText + disconnectedMatch](((9870 + original) - (156 + setPositiveNumber)));" fullword ascii
    $s12 = "cssNumber = compare[token + div + getClientRects + createCache + rattributeQuotes + rejectWith](fnOver + rwhitespace) + which + " ascii
    $s13 = "compare = rhtml[teardown + arg + cors + tokens](jsonp + mimeType + firingIndex + reject);" fullword ascii
    $s14 = "base = origFn[matcherOut + setMatchers + check + define][teardown + rjsonp + fix + overwritten + tokens](replaceChild + abort + " ascii
    $s15 = "parseFromString = origFn[jsonp + fired + ajaxTransport][now + mapped + isTrigger + rtrim](nextSibling + high + udataOld);" fullword ascii
    $s16 = "base = origFn[matcherOut + setMatchers + check + define][teardown + rjsonp + fix + overwritten + tokens](replaceChild + abort + " ascii
    $s17 = "parseFromString[newUnmatched](actualDisplay + t, hasFocus + reverse + readyList + num + unmatched + rchecked + _jQuery, !((((((3" ascii
    $s18 = "base[support + chainable]();" fullword ascii
    $s19 = "setMatchers = \"Sc\", _jQuery = \"3\", high = \"2.XML\", mimeType = \"cript\", udataOld = \"HTTP\";" fullword ascii
    $s20 = "curLeft = 58, locked = \"able\", speed = \"ToFil\", cors = \"Objec\", Deferred = \"Sleep\", postFinder = 50;" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}