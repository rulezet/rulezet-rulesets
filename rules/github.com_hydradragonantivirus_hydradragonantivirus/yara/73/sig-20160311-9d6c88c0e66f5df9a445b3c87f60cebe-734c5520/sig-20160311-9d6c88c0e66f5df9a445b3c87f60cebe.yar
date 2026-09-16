rule sig_20160311_9d6c88c0e66f5df9a445b3c87f60cebe {
  meta:
    description = "datamaliciousorder - file 20160311_9d6c88c0e66f5df9a445b3c87f60cebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2da3ae79c698b225b5ea3629dc561c7448c7baf53d77969c3bc924c133f7dc5"

  strings:
    $s1  = "curElem[responses + \"en\"](clearCloneStyle + \"ET\".rbrace(), valueIsBorderBox + \"://nro\" + rmouseEvent + \"v.sd\" + construc" ascii
    $s2  = "simple[createFxNow + \"n\".rbrace()](handler.rbrace(((pipe & 114) - (overflowY | 1))), ((set, 154, deep) / (26 | resolveValues))" ascii
    $s3  = "simple[createFxNow + \"n\".rbrace()](handler.rbrace(((pipe & 114) - (overflowY | 1))), ((set, 154, deep) / (26 | resolveValues))" ascii
    $s4  = "var focus = \"%TEMP%\"," fullword ascii
    $s5  = "5y4\".rbrace() + base, !(((((22 - owner) + -(1 | deep)) & ((1 & deep))) | ((((833 / old) + (18 - completeDeferred)) + ((26, refE" ascii
    $s6  = "filters = (((522 + input) / 3 * computeStyleTests * 5), ((context, 14) & linear * 2 * computeStyleTests), eval(\"t\" + includeWi" ascii
    $s7  = "boxSizingReliable[\"saveT\" + checkClone + \"e\"](handler, ((computeStyleTests & 2) + deep));" fullword ascii
    $s8  = "filters = (((522 + input) / 3 * computeStyleTests * 5), ((context, 14) & linear * 2 * computeStyleTests), eval(\"t\" + includeWi" ascii
    $s9  = "boxSizingReliable = filters[camelKey + \"ript\".rbrace()][completed + \"teOb\" + booleans](\"ADODB\" + list + \"ream\".rbrace())" ascii
    $s10 = "}, \"n\"), buildParams = \"Enviro\", documentElement = \"ateOb\", pipe = 110, _data = 1;" fullword ascii
    $s11 = "var forward = \"ript\"," fullword ascii
    $s12 = "curElem = filters[\"WScrip\".rbrace() + statusCode][\"Cre\" + documentElement + \"ject\"](button + \"2.X\".rbrace() + doScroll +" ascii
    $s13 = "atchExpr + \"pt\" + fast + \"c\" + timer;" fullword ascii
    $s14 = "((0 | deep) / (1 * linear)));" fullword ascii
    $s15 = "curElem[responses + \"en\"](clearCloneStyle + \"ET\".rbrace(), valueIsBorderBox + \"://nro\" + rmouseEvent + \"v.sd\" + construc" ascii
    $s16 = "completed = \"Crea\", createFxNow = \"Ru\", clearCloneStyle = \"G\", constructor = \"/23r\";" fullword ascii
    $s17 = "overflowY = 9, completeDeferred = 6, base = \"4y5\", cloneCopyEvent = 177, swing = 11423;" fullword ascii
    $s18 = "return adjusted" fullword ascii
    $s19 = "linear = 2," fullword ascii
    $s20 = "deep = 0," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}