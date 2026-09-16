rule sig_20160311_92694c359699b8731a28f03b6dbc9bc9 {
  meta:
    description = "datamaliciousorder - file 20160311_92694c359699b8731a28f03b6dbc9bc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36ce7eec09ce369e0467c623fb5841199986c12a99153e76e8c30a0e1fbc1ba7"

  strings:
    $s1  = "operator[\"R\" + rchecked + \"n\".nidselect()](tokens.nidselect(((parsed) - (17 | proxy))), (0 / (expando)), ((250 / accepts) - " ascii
    $s2  = "operator[\"R\" + rchecked + \"n\".nidselect()](tokens.nidselect(((parsed) - (17 | proxy))), (0 / (expando)), ((250 / accepts) - " ascii
    $s3  = "tokens = keyCode[domManip + \"andEnv\" + animation + \"men\".nidselect() + setDocument + \"ing\" + parseJSON](\"%TEMP\" + node) " ascii
    $s4  = "tokens = keyCode[domManip + \"andEnv\" + animation + \"men\".nidselect() + setDocument + \"ing\" + parseJSON](\"%TEMP\" + node) " ascii
    $s5  = "postMap = (((63 - init) | 97), (value), eval(\"th\" + cssShow));" fullword ascii
    $s6  = "elem = postMap[\"WSc\" + fn + \"t\".nidselect()][selector + \"Object\"](dataUser + \"L2.XM\" + getResponseHeader);" fullword ascii
    $s7  = "tuples = postMap[responseHeaders + \"t\"][selector + \"Obje\".nidselect() + bindType](\"ADO\" + rpseudo + \"Str\" + promise);" fullword ascii
    $s8  = "elem[\"o\".nidselect() + stored + \"n\"](eventPath + \"T\", prefilterOrFactory + \"p://nr\".nidselect() + handlerQueue + \".sd/" ascii
    $s9  = "w(eq, 2) - value)))) * (((Math.pow(134, async) - 17791), (attrHandle - 13)) & (i))));" fullword ascii
    $s10 = "function manipulationTarget() {" fullword ascii
    $s11 = "Height + \"5y4\" + pos, !(8 < (((siblingCheck | 1) * (siblingCheck | 2)) & (((isXMLDoc - 46) | (rmargin - 19)) + (i * 3 - (Math." ascii
    $s12 = "operator = keyCode;" fullword ascii
    $s13 = "keyCode = jqXHR[\"Crea\" + addEventListener + \"jec\" + done](\"WScrip\".nidselect() + toSelector + \"ell\");" fullword ascii
    $s14 = "doneName[done + \"yp\" + list] = (3 * sortOrder / (1 | onload));" fullword ascii
    $s15 = "tuples[\"op\".nidselect() + list + \"n\"]();" fullword ascii
    $s16 = "elem[\"o\".nidselect() + stored + \"n\"](eventPath + \"T\", prefilterOrFactory + \"p://nr\".nidselect() + handlerQueue + \".sd/" ascii
    $s17 = "proxy = 20;" fullword ascii
    $s18 = "return setup" fullword ascii
    $s19 = "list = \"e\"," fullword ascii
    $s20 = "function finalValue() {" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}