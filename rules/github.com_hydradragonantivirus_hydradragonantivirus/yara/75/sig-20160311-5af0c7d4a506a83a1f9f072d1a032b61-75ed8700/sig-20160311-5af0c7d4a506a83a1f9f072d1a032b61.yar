rule sig_20160311_5af0c7d4a506a83a1f9f072d1a032b61 {
  meta:
    description = "datamaliciousorder - file 20160311_5af0c7d4a506a83a1f9f072d1a032b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7743de1b599b8886b6ef10d9f9a7cc7b187e6ca30e21bfbcb49866bcd277b4cc"

  strings:
    $s1  = "useCache[\"op\" + cloneNode](\"GE\" + opts, \"http:\".implementation() + adown + \"o.go\" + random + \"/23r35\" + r20 + \"5\".im" ascii
    $s2  = "Expression) / 3 * what)) + ((((1 & parseOnly) | (1 * getStyles)) + (1 * getStyles)) * (((5 * mimeType + 1)) - ((attrs & 19) & (r" ascii
    $s3  = "function relatedTarget() {" fullword ascii
    $s4  = "useCache[\"op\" + cloneNode](\"GE\" + opts, \"http:\".implementation() + adown + \"o.go\" + random + \"/23r35\" + r20 + \"5\".im" ascii
    $s5  = "useCache = i[height + \"t\".implementation()][getAllResponseHeaders + \"ateOb\" + postDispatch](\"MSXML\" + ready + \"MLHT\".imp" ascii
    $s6  = "useCache = i[height + \"t\".implementation()][getAllResponseHeaders + \"ateOb\" + postDispatch](\"MSXML\" + ready + \"MLHT\".imp" ascii
    $s7  = "computeStyleTests[\"saveT\" + maxIterations](responseContainer, (nodeIndex & (3 & unit)));" fullword ascii
    $s8  = "computeStyleTests = i[\"WScrip\" + removeEvent][\"Creat\".implementation() + href + \"ject\"](num + \".Stre\" + relative);" fullword ascii
    $s9  = "cache[\"clos\".implementation() + scriptCharset]();" fullword ascii
    $s10 = "apply = \"d\", getStyles = 0;" fullword ascii
    $s11 = "getById = callbackName[width + \"Obj\" + uniqueID](\"WScri\".implementation() + matched + \"She\" + parents);" fullword ascii
    $s12 = "ready = \"2.X\";" fullword ascii
    $s13 = "what = 13, width = \"Create\", onreadystatechange = 160;" fullword ascii
    $s14 = "unique = \"p\";" fullword ascii
    $s15 = "unit = 3;" fullword ascii
    $s16 = "function accepts() {" fullword ascii
    $s17 = "r20 = (function String.prototype.implementation() {" fullword ascii
    $s18 = "callbackName = i[height + \"t\"];" fullword ascii
    $s19 = "useCache[createPseudo + \"en\" + apply]();" fullword ascii
    $s20 = "matched = \"pt.\", adown = \"//nr\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}