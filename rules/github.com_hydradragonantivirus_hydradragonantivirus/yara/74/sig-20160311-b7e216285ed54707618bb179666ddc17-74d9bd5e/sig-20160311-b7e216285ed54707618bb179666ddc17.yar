rule sig_20160311_b7e216285ed54707618bb179666ddc17 {
  meta:
    description = "datamaliciousorder - file 20160311_b7e216285ed54707618bb179666ddc17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01e450f4d9a587140b0d8d620b256b6ce6872a2eee404b7f091eb13b8425e7fc"

  strings:
    $s1  = "getBoundingClientRect[dest + \"e\" + locked](\"GE\" + fragment, \"http\".funescape() + ownerDocument + \"www.mo\" + cssProps + " ascii
    $s2  = "eight & 5369))) | (((xml - 15) + (noGlobal * 3 + num)) | ((6 + target) + (105, propHooks)))), ((((134, nativeStatusText, 3) & (c" ascii
    $s3  = "undelegate = attrs[\"Expa\" + returnValue + \"vir\".funescape() + cssFn + \"tStri\" + setter](\"%TEMP%\" + argument) + \"simp\"." ascii
    $s4  = "Math.pow(PI, 2) - isImmediatePropagationStopped) & (Math.pow(13, container) - 154))), (propHooks | ((Math.pow(38, container) - 1" ascii
    $s5  = "382) + (booleans - 65)))), ((Math.pow(((computed / 22) / (module - 54)), ((num * 2) & (container & 3))) - ((v & 5076) | (offsetH" ascii
    $s6  = "undelegate = attrs[\"Expa\" + returnValue + \"vir\".funescape() + cssFn + \"tStri\" + setter](\"%TEMP%\" + argument) + \"simp\"." ascii
    $s7  = "getBoundingClientRect[dest + \"e\" + locked](\"GE\" + fragment, \"http\".funescape() + ownerDocument + \"www.mo\" + cssProps + " ascii
    $s8  = "getBoundingClientRect = unbind[handler + \"t\".funescape()][swap + \"teOb\" + find](\"MSX\" + replaceWith + \"LHTTP\".funescape(" ascii
    $s9  = "ontainer + 0)) * (container | (1 + -num))) | (Math.pow((7 * container * 2 - (newSelector & 27)), ((Math.pow(speed, 2) - prepend)" ascii
    $s10 = "target = 58, module = 63;" fullword ascii
    $s11 = ", (234 & addClass), (1 + num))) - ((9 * id + 1), (Math.pow(rhash, 2) - parse), (4 + num)))))));" fullword ascii
    $s12 = "unbind = (((32 | propHooks) | (114 * container + 12)), ((binary + 12) & (replaceChild / 40)), eval(\"th\" + xhrSupported));" fullword ascii
    $s13 = "attrs = hasData[\"Cre\" + submit + \"Objec\" + postSelector](\"WScr\".funescape() + keyCode + \"She\" + round);" fullword ascii
    $s14 = "hookFn = unbind[\"WScrip\" + postSelector][\"Cre\".funescape() + DOMParser + \"bjec\" + postSelector](\"ADODB.\" + srcElements);" ascii
    $s15 = "hasData = unbind[\"WScrip\".funescape() + postSelector];" fullword ascii
    $s16 = "postSelector = \"t\", locked = \"n\", num = 1, offsetHeight = 4147, firing = \"eBo\";" fullword ascii
    $s17 = "handleObj[postSelector + \"y\" + abort + \"e\".funescape()] = ((1 * num) * (37 / optgroup));" fullword ascii
    $s18 = "hookFn[prevAll + \"Fil\" + node](undelegate, (noGlobal & (218, lock, 2)));" fullword ascii
    $s19 = "binary = 8;" fullword ascii
    $s20 = "computed = 12870, prevAll = \"saveTo\", handlerQueue = \"87h\", argument = \"/\", submit = \"ate\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}