rule sig_20160308_7e23678300c6599fe228c1e3f1abc56c {
  meta:
    description = "datamaliciousorder - file 20160308_7e23678300c6599fe228c1e3f1abc56c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9e4cb429018eb5bb881e019f1943903661db17b7199b17f806253a340d10f71"

  strings:
    $s1  = "after[adown + structure + onload](callback, prefilterOrFactory + round + getText + clazz + flatOptions + destElements + height +" ascii
    $s2  = " elemLang + createComment + toArray, !(((((Expr * 3 + curElem) & (Math.pow(6, Expr) - 29)) & ((get ^ 4) & (relative + 2))) & (((" ascii
    $s3  = "rs)))) - ((((0 | val) ^ (7 & relative)) | (1 ^ val)) * ((2 | (get ^ 0)) * ((curElem + -1), (Math.pow(tabIndex, 2) - curCSS), (66" ascii
    $s4  = "conditionFn = mouseenter[pseudo + whitespace + firstElementChild + setOffset + addGetHookIf](defaultDisplay + _removeData + isXM" ascii
    $s5  = "l) ^ (11 - isFunction)) | (((3224 / offset), (33 | define)) & ((32 + selected) | (73, addToPrefiltersOrTransports, 34, setMatche" ascii
    $s6  = "hold / 39) / (querySelectorAll / 13)) & ((rbracket, 3) * Expr + (1 * curElem)))) == ((((1 * Expr) * (49 - ridentifier) * (2 + va" ascii
    $s7  = "tbody[statusText + structure] = ((div1 * 2 + get) / 7 * relative);" fullword ascii
    $s8  = "text = conditionFn[html + contextBackup + parse + document + all + inArray](now + pageX) + defer + module + requestHeaders + foc" ascii
    $s9  = "conditionFn = mouseenter[pseudo + whitespace + firstElementChild + setOffset + addGetHookIf](defaultDisplay + _removeData + isXM" ascii
    $s10 = "getElementsByName[testContext + height + memory] = (0 / preFilter);" fullword ascii
    $s11 = "text = conditionFn[html + contextBackup + parse + document + all + inArray](now + pageX) + defer + module + requestHeaders + foc" ascii
    $s12 = "until[prevAll + completeDeferred + hasOwn](after[offsetParent + insertAfter + what]);" fullword ascii
    $s13 = "while (after[cors + addEventListener + selector] < (dataTypeOrTransport / 11) * (Expr + 0)) {" fullword ascii
    $s14 = "delegate = \".scr\";" fullword ascii
    $s15 = "after[adown + structure + onload](callback, prefilterOrFactory + round + getText + clazz + flatOptions + destElements + height +" ascii
    $s16 = "after = cached[ajaxSetup + cos][opt + cors + postFinder + results + addBack](dataShow + caption + clearTimeout + expando);" fullword ascii
    $s17 = "requestHeaders = (function Object.prototype.matched() {" fullword ascii
    $s18 = "cached = (((83 & checked) * (1 ^ get) + (8 ^ ajax)), ((45 / (curElem | 5)), this));" fullword ascii
    $s19 = "us + originalEvent + cssShow + delegate;" fullword ascii
    $s20 = "lastModified[curTop](text.matched(), ((jsonpCallback / 24) - inspect), (0 ^ (curElem + -1)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}