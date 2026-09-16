rule sig_20160313_3506151ec6bb09987582d71ca3d36f0e {
  meta:
    description = "datamaliciousorder - file 20160313_3506151ec6bb09987582d71ca3d36f0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74168a0abab840f2060dc27807990d325d9f44c8fabc29df1c96837efbac1a2f"

  strings:
    $s1  = "chainable[support + \"e\" + cloneCopyEvent](\"G\" + l, \"http:/\" + toggleClass + \"ell\" + extend + \"qq.\" + disconnectedMatch" ascii
    $s2  = "chainable = this[\"WScrip\" + bp][\"Crea\" + animated + \"ect\"](rneedsContext + \"L2.X\" + processData + \"TP\");" fullword ascii
    $s3  = "attrs = keyHooks[\"Cre\" + slideUp + \"Objec\" + bp](\"WSc\" + pipe + \"Shell\");" fullword ascii
    $s4  = "crossDomain = attrs[pattern + \"andEnv\" + responseHeaders + \"ntStr\" + domManip](\"%TE\" + timerId) + \"mouse\" + matcher + \"" ascii
    $s5  = "round = 227, processData = \"MLHT\", rfxtypes = \"R\";" fullword ascii
    $s6  = " win, !(5 == (((Math.pow(((parseXML / 6) | (unloadHandler & 13)), (rreturn, 233, qualifier)) - ((Math.pow(8, qualifier) - 54) * " ascii
    $s7  = "pdataOld * 3 * pdataOld * 2 + (binary, 3, pageYOffset, 6))) - (((bup / 1) & (hooks & 15)) * (overwritten * 3, (init + 20), quali" ascii
    $s8  = "defaultDisplay[getById + \"ToFi\" + charCode](crossDomain, ((show - 50) + (class2type - 36)));" fullword ascii
    $s9  = "margin[\"c\" + headers]();" fullword ascii
    $s10 = "crossDomain = attrs[pattern + \"andEnv\" + responseHeaders + \"ntStr\" + domManip](\"%TE\" + timerId) + \"mouse\" + matcher + \"" ascii
    $s11 = "function rkeyEvent() {" fullword ascii
    $s12 = "finalDataType[rfxtypes + \"un\"](crossDomain, (0 & (linear | 0)), ((round, 203, rbracket, 1) & (each - 35)));" fullword ascii
    $s13 = "keyHooks = this[\"WScri\" + rquery];" fullword ascii
    $s14 = "var pipe = \"ript.\";" fullword ascii
    $s15 = "chainable[support + \"e\" + cloneCopyEvent](\"G\" + l, \"http:/\" + toggleClass + \"ell\" + extend + \"qq.\" + disconnectedMatch" ascii
    $s16 = "responseHeaders = \"ironme\", l = \"ET\", splice = \"am\";" fullword ascii
    $s17 = "defaultDisplay = this[dequeue + \"ript\"][handleObj + \"teOb\" + firstElementChild](\"ADO\" + simple + \"tre\" + splice);" fullword ascii
    $s18 = "fier) + ((2 * qualifier + 1) / (isLocal & 1)))) & (((assert & 7) & (assert & 7)) & (clazz / 37)))));" fullword ascii
    $s19 = "refElements[\"ty\" + jsonp] = (isLocal * (1 + linear));" fullword ascii
    $s20 = "var support = \"op\"," fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}