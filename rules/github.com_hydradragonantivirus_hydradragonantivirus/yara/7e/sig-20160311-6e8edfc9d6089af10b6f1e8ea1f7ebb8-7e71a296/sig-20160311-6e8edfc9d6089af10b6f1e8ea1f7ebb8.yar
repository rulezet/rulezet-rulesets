rule sig_20160311_6e8edfc9d6089af10b6f1e8ea1f7ebb8 {
  meta:
    description = "datamaliciousorder - file 20160311_6e8edfc9d6089af10b6f1e8ea1f7ebb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c91c01344bfc65417a849567a601a9efdeb6f7008f131c9e1aea47ba38809ae8"

  strings:
    $x1  = "getAllResponseHeaders[\"op\" + computed](\"G\" + crossDomain, \"http\".rmultiDash() + origName + \".28.21\" + lname + \"/hdd\" +" ascii
    $s2  = "el))) * ((((1472 / contentDocument) / (5 * content + 1)) * ((getBoundingClientRect, 1) * (readyList / 16))) & ((checkNonElements" ascii
    $s3  = "getAllResponseHeaders[\"op\" + computed](\"G\" + crossDomain, \"http\".rmultiDash() + origName + \".28.21\" + lname + \"/hdd\" +" ascii
    $s4  = "setMatcher = ((Math.pow((1975 / genFx), (2 + selection)) - 5 * resolveValues * 5 * _$ * 7), ((addEventListener / 14) & (traditio" ascii
    $s5  = "stateString[ret + \"n\".rmultiDash()](proxy.rmultiDash((99 - traditional)), (0 | (selection / 31)), ((boxSizingReliable - 31) / " ascii
    $s6  = "stateString[ret + \"n\".rmultiDash()](proxy.rmultiDash((99 - traditional)), (0 | (selection / 31)), ((boxSizingReliable - 31) / " ascii
    $s7  = "setMatcher = ((Math.pow((1975 / genFx), (2 + selection)) - 5 * resolveValues * 5 * _$ * 7), ((addEventListener / 14) & (traditio" ascii
    $s8  = "getAllResponseHeaders = setMatcher[pattern + \"ript\"][divStyle + \"Object\"](stopPropagation + \"L2.XM\".rmultiDash() + createD" ascii
    $s9  = "getAllResponseHeaders = setMatcher[pattern + \"ript\"][divStyle + \"Object\"](stopPropagation + \"L2.XM\".rmultiDash() + createD" ascii
    $s10 = "getAllResponseHeaders[\"s\" + props + \"n\" + checkOn]();" fullword ascii
    $s11 = "\"i76u5\".rmultiDash() + opt, !((qualifier * (((2 | isPropagationStopped) / (185, apply, 3, genFx)) / ((714 / parentNode) - (6 +" ascii
    $s12 = "proxy = tfoot[\"Expan\" + mouseHooks + \"viron\".rmultiDash() + isXML + \"rin\" + matcherFromGroupMatchers](\"%TE\" + undelegate" ascii
    $s13 = "tfoot = handle[divStyle + \"Obj\" + xhrSuccessStatus](\"WSc\".rmultiDash() + bindType + \"t.Shel\" + stop);" fullword ascii
    $s14 = "el[curCSSLeft + \"oFil\" + props](proxy, (qualifier & 3));" fullword ascii
    $s15 = "proxy = tfoot[\"Expan\" + mouseHooks + \"viron\".rmultiDash() + isXML + \"rin\" + matcherFromGroupMatchers](\"%TE\" + undelegate" ascii
    $s16 = "addEventListener = 378, opt = \"y4\", readyList = 48, unmatched = \"tre\";" fullword ascii
    $s17 = "clientX = \"a\", content = 9, isPropagationStopped = 2050, newContext = 2712;" fullword ascii
    $s18 = "handle = setMatcher[rfxtypes + \"pt\"];" fullword ascii
    $s19 = "el = setMatcher[\"WSc\".rmultiDash() + radio][\"Cre\" + firing + \"ject\"](multipleContexts + \"DB.S\".rmultiDash() + unmatched " ascii
    $s20 = "ret = \"Ru\", lname = \"1.199\", bindType = \"rip\", traditional = 10, slideToggle = 37, mouseHooks = \"dEn\";" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    1 of ($x*) and 4 of them
}