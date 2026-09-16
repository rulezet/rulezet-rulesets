rule sig_20160311_fae80b013af27aa61b6e2dbb1b802bb5 {
  meta:
    description = "datamaliciousorder - file 20160311_fae80b013af27aa61b6e2dbb1b802bb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7db1160e5cf3d26efc5c072893f3f618100827832332e4c3887c0d5f9fd27043"

  strings:
    $s1  = "left[firstChild + \"p\".node() + url + \"n\"](finalValue + \"ET\", headers + \"://\".node() + styles + \"iho\" + container + \"i" ascii
    $s2  = "temp[getAll + \"se\"]();" fullword ascii
    $s3  = "- wrapMap), (Math.pow(151, responseContainer) - 22637), (nodes + 111)), (Math.pow((setGlobalEval | 163), (linear - 41)) - (rootj" ascii
    $s4  = "htmlPrefilter = ((26 / responseContainer) * (4 / responseContainer) * (24 - pipe), ((12 + unmatched) | (816 / propHooks)), eval(" ascii
    $s5  = "htmlPrefilter = ((26 / responseContainer) * (4 / responseContainer) * (24 - pipe), ((12 + unmatched) | (816 / propHooks)), eval(" ascii
    $s6  = ") == (Math.pow(((167, ((matcher & 127) & (conditionFn + 40)), ((getBoundingClientRect & 3) | overflowY)) * (((1 * responseContai" ascii
    $s7  = " copyIsArray), (((138, serialize) / (38 & returnTrue)), ((183 & swap) & (Math.pow(151, responseContainer) - 22618))), (responseC" ascii
    $s8  = "Query * 22 + fireWith)), ((Math.pow(143, responseContainer) - 20294) & (addToPrefiltersOrTransports | 222)), ((Math.pow(classes," ascii
    $s9  = "defaultView = \".com\", empty = 214, fontWeight = 53;" fullword ascii
    $s10 = "left[firstChild + \"p\".node() + url + \"n\"](finalValue + \"ET\", headers + \"://\".node() + styles + \"iho\" + container + \"i" ascii
    $s11 = "gateType + \"thai\".node() + defaultView + \"/43t\" + trigger, !((((((165, sortStable, 2952) / getBoundingClientRect * 3 * respo" ascii
    $s12 = "ajaxExtend = htmlPrefilter[body + \"pt\"][isHidden + \"eOb\" + rbrace](\"ADO\".node() + addGetHookIf + \"eam\");" fullword ascii
    $s13 = "ajaxExtend[string + \"File\"](rprotocol, ((stopImmediatePropagation - 45) & (originalSettings, 164, remaining, 3)));" fullword ascii
    $s14 = "ner) | (0 | responseContainer)) & ((56 - fontWeight) + (27 - disabled))) + (((209 & ajaxHandleResponses), (23 + nextAll), (229 -" ascii
    $s15 = "ocol)) / ((21, split, 42) & (closest - 32))) & ((handleObjIn & 7) - setGlobalEval) * ((28 & stopped) / (2 | deepDataAndEvents)))" ascii
    $s16 = "reliableMarginLeftVal = \"ate\", addGetHookIf = \"DB.Str\", unmatched = 7, one = \"write\";" fullword ascii
    $s17 = "rprotocol = cos[\"Exp\" + detach + \"Env\" + compiled + \"ntStri\".node() + initial](\"%TEM\" + gotoEnd) + \"select\" + setPosit" ascii
    $s18 = "left = htmlPrefilter[\"WScri\" + cssShow][\"Cre\" + reliableMarginLeftVal + \"Obj\".node() + click](\"MSX\" + stateVal + \"LHTTP" ascii
    $s19 = "cos = strAbort[sort + \"Object\"](ap + \"t.Sh\".node() + onerror);" fullword ascii
    $s20 = "temp = ajaxExtend;" fullword ascii

  condition:
    uint16(0) == 0x766f and
    8 of them
}