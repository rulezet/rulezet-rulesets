rule sig_20160325_23275b2c248d78530082f9190b5f5041 {
  meta:
    description = "datamaliciousorder - file 20160325_23275b2c248d78530082f9190b5f5041.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b9439698a94654957499bbff5aced77ccf4e7bb12d56f99ee8adc025bb733d5"

  strings:
    $s1  = "orig = defaultView[timeStamp + \"eObjec\" + unbind](\"WScr\" + rtrim + \"Shell\");" fullword ascii
    $s2  = "var qsaError = [][\"cons\" + param + \"or\"][timers + \"otype\"][rmsPrefix + \"r\" + unbind][\"appl\" + Expr]();" fullword ascii
    $s3  = "innerText(postMap, setMatchers, binary, first);" fullword ascii
    $s4  = "not = \"ject\", getPropertyValue = 129, first = \"pix\", dir = \"nvir\";" fullword ascii
    $s5  = "nidselect[argument + \"e\" + propName + \"d\"]();" fullword ascii
    $s6  = "maxIterations = new unqueued[\"Act\" + promise + \"XOb\" + not](\"ADOD\" + opener + \"ream\");" fullword ascii
    $s7  = "on = orig[bp + \"andE\" + dir + \"onme\" + speed + \"trin\" + namespaces](\"%TE\" + responseFields + \"/\") + first + \"elPosi\"" ascii
    $s8  = "unqueued[\"WSc\" + hooks][\"Sleep\"](((accepts | 198768) / (stop & 63)));" fullword ascii
    $s9  = "defaultView[strAbort](((2343 | image) * 2 + (ret + 50)));" fullword ascii
    $s10 = "\".\" + argument + \"c\" + isArrayLike;" fullword ascii
    $s11 = "on = orig[bp + \"andE\" + dir + \"onme\" + speed + \"trin\" + namespaces](\"%TE\" + responseFields + \"/\") + first + \"elPosi\"" ascii
    $s12 = "binary = \"dy\";" fullword ascii
    $s13 = "function proxy(superMatcher, selectedIndex, unquoted, stopped) {" fullword ascii
    $s14 = "eval(id(\"proxy%28on%2C%20maxIterations%2C%20%28%28setMatchers%7C0%29%29%2C%20file%20+%20%22oFi%22%20+%20msMatchesSelector%29%3B" ascii
    $s15 = "unbind = \"t\";" fullword ascii
    $s16 = "return qsaError;" fullword ascii
    $s17 = "eval(id(\"proxy%28on%2C%20maxIterations%2C%20%28%28setMatchers%7C0%29%29%2C%20file%20+%20%22oFi%22%20+%20msMatchesSelector%29%3B" ascii
    $s18 = "argument = \"s\"," fullword ascii
    $s19 = "function responses() {" fullword ascii
    $s20 = "register();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}