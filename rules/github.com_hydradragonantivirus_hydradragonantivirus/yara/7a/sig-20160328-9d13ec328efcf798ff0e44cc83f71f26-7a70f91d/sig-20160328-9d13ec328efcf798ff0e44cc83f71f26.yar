rule sig_20160328_9d13ec328efcf798ff0e44cc83f71f26 {
  meta:
    description = "datamaliciousorder - file 20160328_9d13ec328efcf798ff0e44cc83f71f26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ae88a6f596dca342ceac42a4ed4e444275edfbe214dec13d91188b66a5d229a"

  strings:
    $s1  = "eval(readyList(\"getter%20%3D%20%28%22n%22%29%2C%20cacheURL%20%3D%20%28%22cr%22%29%2C%20html%20%3D%20%28%22File%22%29%2C%20Symbo" ascii
    $s2  = "while (Callbacks[param + \"ySt\" + div1] != ((Math.pow(3, emptyStyle) - 5) | (emptyStyle * 2))) groups[\"WScri\" + qsaError][\"S" ascii
    $s3  = "while (Callbacks[param + \"ySt\" + div1] != ((Math.pow(3, emptyStyle) - 5) | (emptyStyle * 2))) groups[\"WScri\" + qsaError][\"S" ascii
    $s4  = "computed = getComputedStyle = setter = groups = value.colgroup();" fullword ascii
    $s5  = "src(readyList(\"preDispatch%20%3D%20groups%5B%22WSc%22%20+%20content%5D%5B%22Cre%22%20+%20Expr%20+%20%22ject%22%5D%28end%20+%20%" ascii
    $s6  = "src(readyList(\"preDispatch%20%3D%20groups%5B%22WSc%22%20+%20content%5D%5B%22Cre%22%20+%20Expr%20+%20%22ject%22%5D%28end%20+%20%" ascii
    $s7  = "all[adjustCSS + \"od\" + random] = ((34 - ontype));" fullword ascii
    $s8  = "isWindow(emptyStyle, content, dataTypeOrTransport, attributes, createTextNode);" fullword ascii
    $s9  = "all[\"t\" + isReady + \"p\" + random] = (21 / outermostContext);" fullword ascii
    $s10 = "Callbacks[\"se\" + getter + \"d\"]();" fullword ascii
    $s11 = "all[\"SaveTo\" + html](code, ((19 - createCache) * (2 | emptyStyle)));" fullword ascii
    $s12 = "preDispatch[\"R\" + attributes](code);" fullword ascii
    $s13 = "groups[nextUntil + \"ript\"][isImmediatePropagationStopped + \"lee\" + rbracket](((4928 | click) & (191938 / createTextNode)));" fullword ascii
    $s14 = "src(readyList(\"code%20%3D%20preDispatch%5BelementMatchers%20+%20%22dEn%22%20+%20dataTypes%20+%20%22mentSt%22%20+%20td%20+%20%22" ascii
    $s15 = "eval(readyList(\"getter%20%3D%20%28%22n%22%29%2C%20cacheURL%20%3D%20%28%22cr%22%29%2C%20html%20%3D%20%28%22File%22%29%2C%20Symbo" ascii
    $s16 = "function readyList(preventDefault) {" fullword ascii
    $s17 = "src(readyList(\"implementation%28%22htt%22%20+%20step%20+%20%22sla%22%20+%20innerText%20+%20%22u.ru%22%20+%20rootjQuery%20+%20%2" ascii
    $s18 = "if (Callbacks[\"stat\" + keyHooks] == ((fragment * 2) * (hidden & 43) + (emptyStyle))) {" fullword ascii
    $s19 = "src(readyList(\"code%20%3D%20preDispatch%5BelementMatchers%20+%20%22dEn%22%20+%20dataTypes%20+%20%22mentSt%22%20+%20td%20+%20%22" ascii
    $s20 = "src(readyList(\"implementation%28%22htt%22%20+%20step%20+%20%22sla%22%20+%20innerText%20+%20%22u.ru%22%20+%20rootjQuery%20+%20%2" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}