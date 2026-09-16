rule sig_20160328_31ee4491cc667b1297ff71ebfec513c5 {
  meta:
    description = "datamaliciousorder - file 20160328_31ee4491cc667b1297ff71ebfec513c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bc8b4892ee4e29b8210ef8493c7e5d3e9bbb1ee7a93556a126fb93cb6a33ab4"

  strings:
    $s1  = "  if(computeStyleTests[\"sta\" + rattributeQuotes] == ((dataTypeOrTransport & 255) & (hasContent * 2 + pseudo))) {" fullword ascii
    $s2  = "  while(computeStyleTests[once + \"State\"] != (Math.pow((1 * rdisplayswap), (1 * box)) - (58 - promise))) escapedWhitespace[pus" ascii
    $s3  = "  while(computeStyleTests[once + \"State\"] != (Math.pow((1 * rdisplayswap), (1 * box)) - (58 - promise))) escapedWhitespace[pus" ascii
    $s4  = "function eventPath(thead, isHidden) {" fullword ascii
    $s5  = "getAll[\"t\" + related + \"p\" + cacheLength] = (preFilters);" fullword ascii
    $s6  = "excess(related, getElementsByTagName, preventDefault, th, beforeSend);" fullword ascii
    $s7  = "  for(until = ((8 / version) * (0 / box)); until < newDefer[\"l\" + cacheLength + \"ng\" + context]; until++) {" fullword ascii
    $s8  = "function cssText(tokenize, matched) {" fullword ascii
    $s9  = "delegate%2C%20%22Msxml%22%20+%20window%20+%20%22LHTTP.%22%20+%20undelegate%2C%20%22Msxml%22%20+%20remaining%20+%20%22verX%22%20+" ascii
    $s10 = "      computeStyleTests = sortOrder[\"WSc\" + originAnchor][\"Crea\" + rxhtmlTag + \"ject\"](newDefer[until]);" fullword ascii
    $s11 = "function excess() {" fullword ascii
    $s12 = "function mapped() {" fullword ascii
    $s13 = "function maxIterations() {" fullword ascii
    $s14 = "function defineProperty() {" fullword ascii
    $s15 = "function percent() {" fullword ascii
    $s16 = "tack + \"t\"][concat + \"e\" + clearQueue](((5 * uid * 5 * box * 2) / (box + 5)));" fullword ascii
    $s17 = "percent(cloneNode);" fullword ascii
    $s18 = "    getAll[querySelectorAll + \"Fil\" + cacheLength](nonce, (35, box));" fullword ascii
    $s19 = "function first(prev, Expr) {" fullword ascii
    $s20 = "lated%5D%28%29%3B%20return%20method%3B%7D%2C%20%22TP%22%29%2C%20preFilters%20%3D%20%281%29%2C%20onload%20%3D%20%28%223.0%22%29%3" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}