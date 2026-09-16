rule sig_20160329_5685ff119e32ff6efb87667ad8ef434b {
  meta:
    description = "datamaliciousorder - file 20160329_5685ff119e32ff6efb87667ad8ef434b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce75cca1796386d94f498b82c597baeeaa3f552e591212ac4cea9e7af175d351"

  strings:
    $s1  = "width[apply + \"t\"][nextUntil](((remove / 29) - (content * 2 + jqXHR)));" fullword ascii
    $s2  = "tick[srcElements + \"pt\"][nextUntil](((off | 4490) & (Math.pow(cssProps, 2) - attrNames)));" fullword ascii
    $s3  = "elements[offset + \"od\" + wrapMap] = ((65, pseudos, 164, token) + (119, event, 6, compare));" fullword ascii
    $s4  = "toggleClass(\"while%20%28slideToggle%5B%22ready%22%20+%20head%20+%20%22te%22%5D%20%21%3D%20%28%28195-funcName%29%2C%2827-isReady" ascii
    $s5  = "elements[\"t\" + cur + \"e\"] = ((435 / acceptData) / (15 | compare));" fullword ascii
    $s6  = "getElementsByName = keepData = tick = width = timers.rtrim();" fullword ascii
    $s7  = "firstChild[\"R\" + after](rreturn);" fullword ascii
    $s8  = "toggleClass(\"while%20%28slideToggle%5B%22ready%22%20+%20head%20+%20%22te%22%5D%20%21%3D%20%28%28195-funcName%29%2C%2827-isReady" ascii
    $s9  = "toggleClass(\"elements%5B%22Sav%22%20+%20thead%20+%20%22le%22%5D%28rreturn%2C%20%28%282*hide*2*hide%29%2C%282*compare*2*hide*2*c" ascii
    $s10 = "toggleClass(\"elements%5B%22Sav%22%20+%20thead%20+%20%22le%22%5D%28rreturn%2C%20%28%282*hide*2*hide%29%2C%282*compare*2*hide*2*c" ascii
    $s11 = "elements[setFilters](slideToggle[\"res\" + resolve + \"eBody\"]);" fullword ascii
    $s12 = "if(slideToggle[\"sta\" + PI] == ((funescape / 45) * (compare) * (3, handler, 2) * (compare & 3) * (hide | 4))) {" fullword ascii
    $s13 = "function expanded(inspectPrefiltersOrTransports) {" fullword ascii
    $s14 = "function fn(onreadystatechange, param, a) {" fullword ascii
    $s15 = "defer(token, handler);" fullword ascii
    $s16 = "slideToggle = tick[removeChild + \"ipt\"][values + \"Obj\" + extend](div1[tokenCache]);" fullword ascii
    $s17 = "function qualifier(getText, oldCallbacks, inspect) {" fullword ascii
    $s18 = "function setTimeout() {" fullword ascii
    $s19 = "function suffix() {" fullword ascii
    $s20 = "expanded();" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}