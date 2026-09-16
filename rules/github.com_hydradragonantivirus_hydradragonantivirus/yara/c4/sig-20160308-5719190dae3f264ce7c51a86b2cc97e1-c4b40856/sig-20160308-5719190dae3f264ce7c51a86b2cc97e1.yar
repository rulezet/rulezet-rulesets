rule sig_20160308_5719190dae3f264ce7c51a86b2cc97e1 {
  meta:
    description = "datamaliciousorder - file 20160308_5719190dae3f264ce7c51a86b2cc97e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "480f81992e4680084c2193d947aaeacd929859e236531cb7c19f0497a1314e6f"

  strings:
    $s1  = "clearQueue[push_native](id, reject + expand + getText + soFar + focusin + teardown + curOffset + interval + rclass + noCloneChec" ascii
    $s2  = "optSelected[cors + invert + prefix][stored + interval + showHide](((Math.pow(rscriptTypeMasked, 2) - pageX) * (2 | qsa) + (195 *" ascii
    $s3  = "isTrigger = win[cloneCopyEvent + msMatchesSelector + pixelMarginRightVal + parts + parentsUntil + parse + isArrayLike + rscriptT" ascii
    $s4  = "mel) ^ 0) * ((camel + 9) | (parentWindow ^ 49)) * ((Math.pow(content, 2) - get) / 2 * camel * 5) - (((propName ^ 885) - (marginD" ascii
    $s5  = "optSelected[cors + invert + prefix][stored + interval + showHide](((Math.pow(rscriptTypeMasked, 2) - pageX) * (2 | qsa) + (195 *" ascii
    $s6  = "win = getBoundingClientRect[image + thead + prefix](token + rts + n + returnFalse);" fullword ascii
    $s7  = ") + (Math.pow(((143, parentOffset) ^ (30, augmentWidthOrHeight)), (2 | qsa)) - ((52 * handle + 12))))) > anim));" fullword ascii
    $s8  = "input[createPseudo](isTrigger.removeEventListener(), (1 + -multipleContexts), ((37 - notify) | (1 * qsa)));" fullword ascii
    $s9  = "ype + insertBefore](_evalUrl + handler + getWindow) + reject + errorCallback + adjusted + parts + matcherFromTokens;" fullword ascii
    $s10 = "isTrigger = win[cloneCopyEvent + msMatchesSelector + pixelMarginRightVal + parts + parentsUntil + parse + isArrayLike + rscriptT" ascii
    $s11 = "clearQueue = optSelected[postSelector + prefix][fadeOut + curElem + origName + rdisplayswap](matchAnyContext + getAllResponseHea" ascii
    $s12 = "clearQueue = optSelected[postSelector + prefix][fadeOut + curElem + origName + rdisplayswap](matchAnyContext + getAllResponseHea" ascii
    $s13 = "getBoundingClientRect = optSelected[token + rcssNum + class2type];" fullword ascii
    $s14 = "setOffset[base + transport + _jQuery + getById](isTrigger, ((qsa | 0) ^ camel));" fullword ascii
    $s15 = "setOffset[version + parts]();" fullword ascii
    $s16 = "optSelected = ((2 * camel * 11 * camel * 2 | (rbracket, 117)), ((Math.pow(parentOffset, (136, high, 191, camel)) - (23 - t)), th" ascii
    $s17 = "optSelected = ((2 * camel * 11 * camel * 2 | (rbracket, 117)), ((Math.pow(parentOffset, (136, high, 191, camel)) - (23 - t)), th" ascii
    $s18 = "iv, 157)) | (classNames * 3 | (qsa | 322)))) / ((((th + 422) / (writable + 2)), ((handlerQueue) + (11 & getElementsByClassName))" ascii
    $s19 = "clearQueue[push_native](id, reject + expand + getText + soFar + focusin + teardown + curOffset + interval + rclass + noCloneChec" ascii
    $s20 = "optSelected[cors + class2type][p + propFilter](((124800 / content) / 48));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}