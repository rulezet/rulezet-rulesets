rule sig_20160313_4bcefbd4aac7b06d0063b4d61bbc4642 {
  meta:
    description = "datamaliciousorder - file 20160313_4bcefbd4aac7b06d0063b4d61bbc4642.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "993dcddd1a6aa1c6354df4184e218185ec6b8edc13b5b06871987fb2f61282c4"

  strings:
    $x1  = "ifModified[\"op\" + xhrFields + \"n\"](cors + \"E\" + eventDoc, \"http\" + originalEvent + \"ellog\" + byElement + \"q.com\" + s" ascii
    $s2  = "ifModified[\"op\" + xhrFields + \"n\"](cors + \"E\" + eventDoc, \"http\" + originalEvent + \"ellog\" + byElement + \"q.com\" + s" ascii
    $s3  = "push = checked[\"Expan\" + dataAndEvents + \"viron\" + hasFocus + \"tStr\" + siblings](\"%TE\" + rnoContent + \"/\") + Data + \"" ascii
    $s4  = ") - (13 * stop + 3)) * ((event, 229, hooks) * 2) + ((postFilter | 132) / (valueParts & 46)))), ((((Math.pow(responseType, 2) - p" ascii
    $s5  = "currentTarget[ownerDocument + \"y\" + specified + \"e\"] = ((35 / active) & (203, hooks));" fullword ascii
    $s6  = " & (125 + stop)) & ((212, holdReady, 253, ofType) & (54 * stop + 18)))), (Math.pow(((Math.pow((Math.pow(iNoClone, 2) - backgroun" ascii
    $s7  = "currentTarget = round;" fullword ascii
    $s8  = "push = checked[\"Expan\" + dataAndEvents + \"viron\" + hasFocus + \"tStr\" + siblings](\"%TE\" + rnoContent + \"/\") + Data + \"" ascii
    $s9  = "parentOffset[getResponseHeader + \"un\"](push, ((defer & 1) / (values | 12)), defer);" fullword ascii
    $s10 = "dClip), 2) - isPropagationStopped)), (((39 / ajaxHandleResponses) * (2 & stop)) + ((1 * hooks) + -(1 | hooks)))) - (((25 | remov" ascii
    $s11 = "round[stopImmediatePropagation + \"oFi\" + dataShow](push, ((14 * documentElement + 7) - (event | 40)));" fullword ascii
    $s12 = "exe\", !(((((7 * documentElement * 3 - (hidden * 4 + replaceWith)) * ((30 | unqueued) | (280 / stopOnFalse))) | (((246 / iNoClon" ascii
    $s13 = " (113 + ct)), (2 + (hooks * 0))) - ((rejectWith + 33899) & (parsed / 24))) / (((domManip - 58) & (method | 14)) & stop * (3 * st" ascii
    $s14 = "eEvent) * (2 | stop) + (1 | defer)) & (3 | defer) * 7 * (documentElement & 3))), ((Math.pow((tokenCache * 13 * documentElement &" ascii
    $s15 = "function thead() {" fullword ascii
    $s16 = "round = this[\"WScrip\" + ownerDocument][\"Create\" + conv2](\"ADOD\" + pseudo + \"tream\");" fullword ascii
    $s17 = "rbracket = this[\"WScr\" + handler];" fullword ascii
    $s18 = "ifModified[now + \"en\" + collection]();" fullword ascii
    $s19 = "ifModified = this[\"WScrip\" + ownerDocument][\"Crea\" + setFilters + \"ct\"](fnOver + \"2.XMLH\" + documentIsHTML);" fullword ascii
    $s20 = "round[curTop + \"en\"]();" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}