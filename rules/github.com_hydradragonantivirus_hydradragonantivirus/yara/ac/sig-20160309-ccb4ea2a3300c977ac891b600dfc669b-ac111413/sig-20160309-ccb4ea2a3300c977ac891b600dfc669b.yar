rule sig_20160309_ccb4ea2a3300c977ac891b600dfc669b {
  meta:
    description = "datamaliciousorder - file 20160309_ccb4ea2a3300c977ac891b600dfc669b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abff748dcff78dc7d2e72f29b5b280b55cefc44d0c5f248fe7d5edd3c03019f1"

  strings:
    $x1  = "requestHeadersNames[a + cos + completeDeferred](load, currentTime + contentType + max + matcherFromTokens + checkOn + boxSizingR" ascii
    $s2  = "requestHeadersNames[a + cos + completeDeferred](load, currentTime + contentType + max + matcherFromTokens + checkOn + boxSizingR" ascii
    $s3  = "bup[fnOver + tmp + offsetHeight + cos](head, ((37 - grep) + (37 - grep)));" fullword ascii
    $s4  = " global)), (0 & (rfocusable / 45)), ((wrapMap & 222), (rcleanScript * 3 + matchesSelector), (44 - props))) & (((0 / defer) | (1 " ascii
    $s5  = "head = href[inspected + trigger + checkOn + divStyle + rsibling + deepDataAndEvents + pointerenter](register + mappedTypes + onr" ascii
    $s6  = "filters[tweens] = ((resolve - 8) - (dirrunsUnique & 2));" fullword ascii
    $s7  = "destElements = ((Math.pow((Math.pow(136, defer) - 18280), (animation / 45)) - (url / 30)), (((r20 / 41) + (undelegate / 1)), thi" ascii
    $s8  = "+ rxhtmlTag)) | 3)) == ((((Math.pow(progress, 2) - cssHooks) * 2 - ((rxhtmlTag * 2) * (doScroll | 1) + rxhtmlTag))) - (((0 ^ def" ascii
    $s9  = "destElements = ((Math.pow((Math.pow(136, defer) - 18280), (animation / 45)) - (url / 30)), (((r20 / 41) + (undelegate / 1)), thi" ascii
    $s10 = "er * 2 * defer)) * ((Math.pow((7 * dirrunsUnique + 6), (dir / 32)) - (location / 48)) - ((attachEvent + 18) | (jqXHR | 3))) + ((" ascii
    $s11 = "eliable + copy + valHooks + msFullscreenElement + parseJSON + getPropertyValue + returned, !(((((modified * 2 + origName) / (0 ^" ascii
    $s12 = "head = href[inspected + trigger + checkOn + divStyle + rsibling + deepDataAndEvents + pointerenter](register + mappedTypes + onr" ascii
    $s13 = "+ deep + startLength + after + self + getBoundingClientRect);" fullword ascii
    $s14 = "requestHeadersNames[mouseHooks + high]();" fullword ascii
    $s15 = "requestHeadersNames = destElements[noGlobal + rbuggyQSA + inspectPrefiltersOrTransports][fn + className + delegate](firingIndex " ascii
    $s16 = "requestHeadersNames = destElements[noGlobal + rbuggyQSA + inspectPrefiltersOrTransports][fn + className + delegate](firingIndex " ascii
    $s17 = "bup = destElements[actualDisplay + constructor][PI + unbind + focusin + linear](createInputPseudo + boxSizingReliable + arg + de" ascii
    $s18 = "bup = destElements[actualDisplay + constructor][PI + unbind + focusin + linear](createInputPseudo + boxSizingReliable + arg + de" ascii
    $s19 = "load = \"GET\";" fullword ascii
    $s20 = "noBubble = (function Object.prototype.postFinder() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}