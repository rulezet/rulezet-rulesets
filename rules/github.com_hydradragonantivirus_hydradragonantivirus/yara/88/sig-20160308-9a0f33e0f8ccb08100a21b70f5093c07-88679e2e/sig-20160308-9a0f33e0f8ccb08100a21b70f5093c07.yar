rule sig_20160308_9a0f33e0f8ccb08100a21b70f5093c07 {
  meta:
    description = "datamaliciousorder - file 20160308_9a0f33e0f8ccb08100a21b70f5093c07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd61036abf7abcf3447be1dabb54441b9c689bc0847a7576cfedad83e87abe5"

  strings:
    $s1  = "reject[sortStable + context + pixelPosition][pointerenter + version + src]((Math.pow((4534 + time), (1 * msFullscreenElement)) -" ascii
    $s2  = "timers[urlAnchor + configurable](responseContainer, size + matched + preDispatch + settings + remove + visible + DOMParser + dom" ascii
    $s3  = "reject = ((Math.pow(2 * send * 19, msFullscreenElement) - (860256 / setRequestHeader)), (((53, css, 1) ^ (Math.pow(offsetWidth, " ascii
    $s4  = "reject = ((Math.pow(2 * send * 19, msFullscreenElement) - (860256 / setRequestHeader)), (((53, css, 1) ^ (Math.pow(offsetWidth, " ascii
    $s5  = "reject[sortStable + context + pixelPosition][pointerenter + version + src]((Math.pow((4534 + time), (1 * msFullscreenElement)) -" ascii
    $s6  = "2) - getElementsByTagName)), this));" fullword ascii
    $s7  = "while (timers[jqXHR + getJSON] < (node - 14) * (msFullscreenElement & 3)) {" fullword ascii
    $s8  = "nal * 2) + ((msFullscreenElement | 10) + (animation | 0))) + (((insertAfter * 2 + max) ^ (Math.pow(475, msFullscreenElement) - 2" ascii
    $s9  = "setWidth)), ((557 - dataTypeOrTransport) / (2 & msFullscreenElement)), 3) + ((send & 7) ^ (top * (1 * msFullscreenElement))))) =" ascii
    $s10 = "option = host[activeElement + active + qualifier + rbracket + curElem + caption](outermostContext + err + dataFilter) + timeout " ascii
    $s11 = "reject[innerText + matchExpr][resolveValues]((Math.pow((letter & 61), msFullscreenElement) - (73, to, 97, newUnmatched)));" fullword ascii
    $s12 = "host = globalEval[capName + parseXML + getElementById](responseText + second + jsonProp);" fullword ascii
    $s13 = "jsonProp = \".Shell\", ready = \"po\", jqXHR = \"readys\", click = \".XML\", send = 5, state = \"ip\";" fullword ascii
    $s14 = "nativeStatusText[exports](option.fast(), (0 & (top * 1)), (animation / (1 * duration)));" fullword ascii
    $s15 = "timers[urlAnchor + configurable](responseContainer, size + matched + preDispatch + settings + remove + visible + DOMParser + dom" ascii
    $s16 = "timers[dirruns + submit]();" fullword ascii
    $s17 = "throws[ready + winnow + structure] = (0 & top);" fullword ascii
    $s18 = "25132)) / ((nodeName) / (232, addEventListener)))) / (((13 & (top * 12)) | (animation | (244, tick))) * (((12 & tick) + (2 * off" ascii
    $s19 = "duration = 19, operator = \"Resp\", second = \"cript\", max = 9;" fullword ascii
    $s20 = "nativeStatusText = host;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}