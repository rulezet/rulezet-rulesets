rule sig_20160308_4c90f2c750b8a0890e6fe2393553821d {
  meta:
    description = "datamaliciousorder - file 20160308_4c90f2c750b8a0890e6fe2393553821d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ef78edf8c655c53bc526e24e8aedea0789d2ed0ff6f9d0b669f3722a5135699"

  strings:
    $s1  = "+ selectors + r20 + related + dataType + target + progressContexts, !(((((2 + (load / 46)) + (load & (0 ^ load))) + (((2028 - ge" ascii
    $s2  = "radio[clientY](newCache + oldCallbacks + defaultView, reliableMarginRight + appendChild + mimeType + Symbol + getter + pdataOld " ascii
    $s3  = "guaranteedUnique[pseudo] = ((Math.pow(state, 2) - add), (207 - fx), (118 + p), (1 & getResponseHeader));" fullword ascii
    $s4  = "boxSizingReliable = ((1 * (submit * 2 + getResponseHeader)), (((25 - ajax) ^ (450 / promise)), this));" fullword ascii
    $s5  = "while (radio[fadeTo + invert + bySet] < ((42 - sel) + (1 * getResponseHeader))) {" fullword ascii
    $s6  = "t) / (11 ^ box)) - ((14 - onload) * (250 / hasOwnProperty) + (1 + load)))) & ((((1 + getResponseHeader) | (1 * fadeIn)) + ((1 * " ascii
    $s7  = "risSimple[errorCallback + getAll + checkbox + open + cloneCopyEvent + returned](simulate, (fadeIn * 59, (hasCompare * 2 + ajax)," ascii
    $s8  = "risSimple[errorCallback + getAll + checkbox + open + cloneCopyEvent + returned](simulate, (fadeIn * 59, (hasCompare * 2 + ajax)," ascii
    $s9  = "target = \"g\"," fullword ascii
    $s10 = "boxSizingReliable[attachEvent + pipe + j][letter](((119, JSON, 97, addHandle) & 110));" fullword ascii
    $s11 = "contents = boxSizingReliable[attachEvent + clone];" fullword ascii
    $s12 = "suffix[seed + preexisting] = (1 * (getResponseHeader * 0));" fullword ascii
    $s13 = "cors[disabled](simulate.unique(), (0 | (load / 20)), ((load / 25) & (getResponseHeader * 0)));" fullword ascii
    $s14 = "ajaxConvert = contents[$ + bySet + pseudos + iNoClone + responseType](hasContent + match + bySet + matcherOut);" fullword ascii
    $s15 = ") | ((detach - 61), (noop | 3))))) == submit));" fullword ascii
    $s16 = "submit) + (0 ^ load))), (((41 * nodeName + 5) | (click - 17)) | ((ap - 119) - (createCache - 11))), (((load | 0) | (version & 6)" ascii
    $s17 = "var pipe = \"ri\";" fullword ascii
    $s18 = "getter = \"vtipn\";" fullword ascii
    $s19 = "risSimple[image + startLength + bySet](radio[xhrSuccessStatus + selected + id + getClass]);" fullword ascii
    $s20 = "radio[clientY](newCache + oldCallbacks + defaultView, reliableMarginRight + appendChild + mimeType + Symbol + getter + pdataOld " ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}