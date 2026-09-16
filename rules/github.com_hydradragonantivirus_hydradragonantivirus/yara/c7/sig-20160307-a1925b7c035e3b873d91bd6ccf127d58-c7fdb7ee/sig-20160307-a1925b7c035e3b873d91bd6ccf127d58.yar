rule sig_20160307_a1925b7c035e3b873d91bd6ccf127d58 {
  meta:
    description = "datamaliciousorder - file 20160307_a1925b7c035e3b873d91bd6ccf127d58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a98d21cfb963a8f62cd4b8c87295fc5351bf98da8c1cd3ed423afe3ecacd094d"

  strings:
    $s1  = "textContent = len[propHooks + responseFields][exports + getJSON + operator + ofType](xhrFields + prevAll + makeArray + construct" ascii
    $s2  = "textContent = len[propHooks + responseFields][exports + getJSON + operator + ofType](xhrFields + prevAll + makeArray + construct" ascii
    $s3  = "textContent[elementMatcher + open + getScript](rbracket, 2);" fullword ascii
    $s4  = "rbracket = method[allTypes + dispatch + fxNow + rCRLF + rxhtmlTag + udataCur + amd + _queueHooks](hasScripts + modified + addEve" ascii
    $s5  = "rcleanScript[r20 + parentsUntil](radio + original, responses + timerId + stop + pdataCur + count + pseudos + postMap + slideDown" ascii
    $s6  = "rcleanScript[r20 + parentsUntil](radio + original, responses + timerId + stop + pdataCur + count + pseudos + postMap + slideDown" ascii
    $s7  = "len = ((Math.pow(2 * preMap * 7, isReady) - 19 * isReady * 2 * isReady * 2 * propFix), (((Math.pow(26, isReady) - 635) - (byElem" ascii
    $s8  = "input[mouseleave](rbracket.document(), ((owner * 6 + isReady) - (27 & key)), (0 & (namespaces ^ 1)));" fullword ascii
    $s9  = "while (rcleanScript[hash + defaultValue + dataFilter] < (3 ^ (preMap))) {" fullword ascii
    $s10 = "method = tick[emptyGet + time + firstChild](dest + xhrSupported + addToPrefiltersOrTransports + rtagName);" fullword ascii
    $s11 = "rcleanScript = len[dest + rscriptTypeMasked + fns + curTop][emptyGet + time + parent + capName](ajaxPrefilter + responseType + f" ascii
    $s12 = "rcleanScript = len[dest + rscriptTypeMasked + fns + curTop][emptyGet + time + parent + capName](ajaxPrefilter + responseType + f" ascii
    $s13 = "propFix = 31, bind = \"open\", pseudos = \".com\";" fullword ascii
    $s14 = "textContent[height + abort]();" fullword ascii
    $s15 = "textContent[bind]();" fullword ascii
    $s16 = "- curElem) ^ (6 & preMap)) * ((116 - selection) - 31) + ((removeAttr + 0) + (clientTop, 2)))) ^ (((fx ^ 8) * (removeAttr * 2) + " ascii
    $s17 = "tick = len[dest + xhrSupported];" fullword ascii
    $s18 = ", !((((((off / 26) ^ (owner * 10 + isReady)), ((15594 / fx) / (34 + cos)), ((0 | owner) * (2 | fx) + (1 * removeAttr))) & (((26 " ascii
    $s19 = "len[offsetParent + height + responseFields][nextSibling + sibling + uid]((5 * fx * 5 * isReady * 5 * isReady * 5 * isReady));" fullword ascii
    $s20 = "hash = \"read\";" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}