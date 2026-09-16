rule sig_20160313_79893420ae282daca5a84328026851c2 {
  meta:
    description = "datamaliciousorder - file 20160313_79893420ae282daca5a84328026851c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "425f9a04d400a35759d6aa06ba937b87101b68203d5f243eb4f32cc1a1dc1886"

  strings:
    $s1  = " 3 * index * 3)) + (((Math.pow(subordinate, 2) - password) / (24 | ignored)), ((1 & marginRight) & 0))) == ((((marginRight + 1) " ascii
    $s2  = "ajax[bp + \"en\"](left + \"T\", visibility + \"p://o\" + reset + \"oguyff\" + view + \"/70.e\" + elem, !(((1 + ((chainable / 19)" ascii
    $s3  = "rnoInnerhtml[hash + \"un\"](tweeners, ((Math.pow(32, index) - 976) - (cssExpand + 45)), ((ignored | 0) & (ignored / 50)));" fullword ascii
    $s4  = "match = selectedIndex[\"Crea\" + _default + \"ect\"](matcherOut + \"t.Shel\" + targets);" fullword ascii
    $s5  = "target();" fullword ascii
    $s6  = "function target() {" fullword ascii
    $s7  = "view = \".com\";" fullword ascii
    $s8  = "input = \"MLHT\", dataAttr = 12, newSelector = \"t\", password = 5486097, _queueHooks = \"ody\";" fullword ascii
    $s9  = "+ (marginRight * 0)) & ((offset * 6 + dataAttr) / 38)) | (((finalText * 4 + marginRight) / (55 - isSimulated)) * (1 * ignored)))" ascii
    $s10 = "ajax[bp + \"en\"](left + \"T\", visibility + \"p://o\" + reset + \"oguyff\" + view + \"/70.e\" + elem, !(((1 + ((chainable / 19)" ascii
    $s11 = "tweeners = match[\"Exp\" + matcher + \"iron\" + cur + \"tStrin\" + uniqueID](\"%TE\" + rbracket + \"/\") + bindType + \"teC\" + " ascii
    $s12 = "tweeners = match[\"Exp\" + matcher + \"iron\" + cur + \"tStrin\" + uniqueID](\"%TE\" + rbracket + \"/\") + bindType + \"teC\" + " ascii
    $s13 = "ajax = this[\"WScri\" + firstChild][\"Crea\" + curTop + \"ject\"](dataTypeExpression + \"ML2.X\" + input + \"TP\");" fullword ascii
    $s14 = " + write + \"c\" + rfxtypes;" fullword ascii
    $s15 = "selectedIndex = this[\"WScrip\" + newSelector];" fullword ascii
    $s16 = "pdataOld = this[\"WScr\" + second][\"Create\" + blur](\"ADODB.\" + style + \"am\");" fullword ascii
    $s17 = "finalText = 4, nativeStatusText = \"p\", hash = \"R\", bp = \"op\";" fullword ascii
    $s18 = "var cloneNode = this;" fullword ascii
    $s19 = "eased = \"omme\", nextAll = \"pon\", style = \"Stre\", second = \"ipt\";" fullword ascii
    $s20 = "left = \"GE\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}