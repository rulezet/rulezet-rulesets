rule sig_20160308_ed9694be6eb678b1f8c27b6d28ed9dea {
  meta:
    description = "datamaliciousorder - file 20160308_ed9694be6eb678b1f8c27b6d28ed9dea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c94ca3142b4cf07c0a40711d46e1afdb54e9c485e39551abdea3b98938fb10"

  strings:
    $s1  = "requestHeadersNames = progressContexts[code + name + values][keepScripts + password + msMatchesSelector](boxSizingReliableVal + " ascii
    $s2  = "createFxNow[newContext + getAttribute](urlAnchor + multipleContexts, udataCur + getText + ajaxSetup + doAnimation + blur + curPo" ascii
    $s3  = "requestHeadersNames = progressContexts[code + name + values][keepScripts + password + msMatchesSelector](boxSizingReliableVal + " ascii
    $s4  = "* readyState)) - (249, rmouseEvent, 214, max)), (1 * readyState)) - (Math.pow((21260 / expando), (2 & click)) - (223154 + ajaxCo" ascii
    $s5  = "1 * button)) & (Math.pow((26 + pixelPositionVal), (2 | readyState)) - (2373 - max))) & (Math.pow((Math.pow((1089 / exports), (1 " ascii
    $s6  = "parts = \"ready\", password = \"ateO\", src = \"h5\", getAll = \"r\", defaultView = \"Create\", ajaxSetup = \"://cy\";" fullword ascii
    $s7  = "sition + which + rprotocol + rsibling + src, !(rfocusable < ((((79 * button * 3 | (argument, 1760)) + ((hasContent - 44) ^ (rnoC" ascii
    $s8  = "while(createFxNow[parts + dataShow + rmultiDash + Expr] < ((32 | completed) - (10 * webkitMatchesSelector))) {" fullword ascii
    $s9  = "mozMatchesSelector = reject[scrollTo + onload + image + makeArray + cloneNode + currentTime](first + startTime) + i + dataShow +" ascii
    $s10 = "createFxNow = progressContexts[push_native + th][copyIsArray + prefilterOrFactory + getElementById + Expr + set + values](origin" ascii
    $s11 = "createFxNow[newContext + getAttribute](urlAnchor + multipleContexts, udataCur + getText + ajaxSetup + doAnimation + blur + curPo" ascii
    $s12 = "requestHeadersNames[value](createFxNow[eventHandle + e + isPropagationStopped]);" fullword ascii
    $s13 = "parentOffset[createTextNode + specialEasing + parse] = (els - 19);" fullword ascii
    $s14 = "progressContexts[code + rbuggyQSA][step + Expr + clientTop](((22439 - checkNonElements) + (289 | isArray)));" fullword ascii
    $s15 = "qsaError = progressContexts[left + values];" fullword ascii
    $s16 = "reject = qsaError[defaultView + orig + Expr + removeAttr](nodeNameSelector + clearQueue + isArrayLike + props);" fullword ascii
    $s17 = "getter = \"send\";" fullword ascii
    $s18 = "createFxNow[getter]();" fullword ascii
    $s19 = "show = requestHeadersNames;" fullword ascii
    $s20 = "show[rnative + checkbox] = (34 / (anim, 34));" fullword ascii

  condition:
    uint16(0) == 0x6562 and
    8 of them
}