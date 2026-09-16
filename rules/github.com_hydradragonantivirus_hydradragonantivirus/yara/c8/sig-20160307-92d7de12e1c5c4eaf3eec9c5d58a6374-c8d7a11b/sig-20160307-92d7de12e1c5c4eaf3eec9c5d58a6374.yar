rule sig_20160307_92d7de12e1c5c4eaf3eec9c5d58a6374 {
  meta:
    description = "datamaliciousorder - file 20160307_92d7de12e1c5c4eaf3eec9c5d58a6374.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c756457a22a50e1e4b4ece16c81ebe4afd5c880cfbb1385eed7eaacb2a152564"

  strings:
    $s1  = "selector[unbind + postSelector](setTimeout + handlers, time + unmatched + get + load + docElem + getStyles + val + fromCharCode " ascii
    $s2  = "+ v + firstElementChild + targets, !((((((0 / xhrSupported) | (768 / code)) - (Math.pow((16 + elemdisplay), (12 - addClass)) - (" ascii
    $s3  = "94, compare))) + (((666 / genFx) ^ (31 ^ curElem)) - ((Math.pow(220, parentWindow) - 48152), (margin + 119), (dataShow / 34), (c" ascii
    $s4  = "_queueHooks[initial + backgroundClip][compile](((Math.pow(156, parentWindow) - 24136) / (returnFalse - 40)));" fullword ascii
    $s5  = "current = _queueHooks[uniqueSort + rkeyEvent + unmatched];" fullword ascii
    $s6  = "selector[unbind + postSelector](setTimeout + handlers, time + unmatched + get + load + docElem + getStyles + val + fromCharCode " ascii
    $s7  = "_queueHooks = (((91 ^ clientLeft) & (23 * active + 18)), ((compare * (11 & getPropertyValue)), this));" fullword ascii
    $s8  = "responseType[cssProps](head.clientTop(), ((isPropagationStopped / 25), (fn, 133, cloneCopyEvent), 0), (compare * 0));" fullword ascii
    $s9  = "(121 - isSuccess), (2 & addCombinator)) - 31 * apply), ((144 / linear) ^ (252 & async)), ((19 - marginDiv) ^ (90, optDisabled, 1" ascii
    $s10 = "488 - end))) | (((34 & fix) & (41 ^ parentWindow)) / ((21 + reliableMarginRight) & (175, qualifier, 16, queue)))) ^ (((Math.pow(" ascii
    $s11 = "fixHooks[handle + iNoClone](selector[throws + pixelPosition + getStyles + isNumeric + beforeunload]);" fullword ascii
    $s12 = "namespaces = current[until + prevObject + offsetHeight + host + lastModified](speed + speeds + stopped + maxIterations + documen" ascii
    $s13 = "fixHooks[m + checked + headers + th](head, (parentWindow + 0));" fullword ascii
    $s14 = "head = namespaces[isPlainObject + arg + rmargin + removeAttribute + prevObject + getAttributeNode + unmatched + box + uid](inser" ascii
    $s15 = "head = namespaces[isPlainObject + arg + rmargin + removeAttribute + prevObject + getAttributeNode + unmatched + box + uid](inser" ascii
    $s16 = "namespaces = current[until + prevObject + offsetHeight + host + lastModified](speed + speeds + stopped + maxIterations + documen" ascii
    $s17 = "_queueHooks[initial + backgroundClip][compile](((dataFilter ^ 599) | (parentNode / 27)));" fullword ascii
    $s18 = "argument[Callbacks + safeActiveElement + firing] = ((rootjQuery, 196, readyState, 1) & (compare * 0));" fullword ascii
    $s19 = "selector = _queueHooks[rcheckableType + oldCache + backgroundClip][content + propFix + hasClass + unmatched](jsonp + option + $ " ascii
    $s20 = "propFix = \"ateOb\", optDisabled = 120, host = \"j\", initial = \"WScr\", cloneCopyEvent = 171;" fullword ascii

  condition:
    uint16(0) == 0x6874 and
    8 of them
}