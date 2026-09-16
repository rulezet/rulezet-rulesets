rule sig_20160308_a448d70660635ece26c3fe749eab5b47 {
  meta:
    description = "datamaliciousorder - file 20160308_a448d70660635ece26c3fe749eab5b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38aaf993f5f7d298e5b749f8294a64560597674851505a6de487fce7e387a451"

  strings:
    $s1  = "url[setTimeout](callback, fixHooks + rCRLF + restoreScript + restoreScript + guid + rsubmittable + sibling + origName + cloneCop" ascii
    $s2  = "doScroll = (((155 - time) ^ (207 - XMLHttpRequest)), ((Math.pow((Math.pow(7, computeStyleTests) - 38), (XMLHttpRequest / 45)) - " ascii
    $s3  = "doScroll = (((155 - time) ^ (207 - XMLHttpRequest)), ((Math.pow((Math.pow(7, computeStyleTests) - 38), (XMLHttpRequest / 45)) - " ascii
    $s4  = "48 & l), (1 + always)) - 21755), ((define / 46) | (Math.pow(stopped, 2) - isReady)), ((Math.pow(6062, computeStyleTests) - 36740" ascii
    $s5  = "(15 * computeStyleTests + 12), stop))), ((Math.pow(((6117 ^ linear) / (74 - count)), (1 * computeStyleTests)) - ((57412 / tokeni" ascii
    $s6  = "url = doScroll[rnumnonpx + nodeName + els][jsonpCallback + hasCompare + attachEvent + opacity](rrun + allTypes + preDispatch + d" ascii
    $s7  = "yEvent + prepend + n + siblingCheck, !((Math.pow(((((always * 8) - (computeStyleTests & 3)) ^ (define ^ 0)) & (((namespace & 47)" ascii
    $s8  = "emoveData ^ 54) ^ ((unqueued / 34) * (tokenize & 7) + (tokenize * 5 + computeStyleTests))), (((161, idx) & 3) * ((qualifier - 50" ascii
    $s9  = " - 180), (define ^ 5)), (computeStyleTests & 3)) - ((Math.pow(DOMParser, 2) - visibility) - 11 * idx))))));" fullword ascii
    $s10 = " / (Math.pow(focusin, 2) - stopped)) & (7 + define))), (((17 * computeStyleTests * 2 * computeStyleTests, (Math.pow(47, computeS" ascii
    $s11 = "doScroll[querySelectorAll + props][isBorderBox + finalText](((13113 ^ teardown) - (Math.pow(9737, computeStyleTests) - 94799195)" ascii
    $s12 = "ze) | (14320 + fix))) - ((5 * booleans * (20 - Sizzle) + (21 + define)) ^ (Math.pow((22 + mouseHooks), (0 ^ computeStyleTests)) " ascii
    $s13 = "doScroll[querySelectorAll + props][isBorderBox + finalText](((13113 ^ teardown) - (Math.pow(9737, computeStyleTests) - 94799195)" ascii
    $s14 = "createInputPseudo = doScroll[querySelectorAll + props][rtypenamespace + deep + overflowX](createComment + $ + lang + rcleanScrip" ascii
    $s15 = "computeStyleTests * 2) - ((err ^ 242), (count | 18))))) == ((((triggerHandler / 42) * computeStyleTests * (90 / DOMParser) * (86" ascii
    $s16 = ") * (rquery | 0)) + ((condense - 10), (offsetHeight, 87, fx, 2))), (Math.pow(((rprotocol / 49), (fragment, 208), (createTextNode" ascii
    $s17 = " / toggle) * 2 + ((seed ^ 202) / (_queueHooks + 1))) * ((err - 11) + always) + ((Math.pow((33 | clientTop), 2) - (selection - 82" ascii
    $s18 = " + 5 * prefix)), (((2 ^ define) * (2 & idx) + (39 - arr)) | ((1588 & bp) / (170, disconnectedMatch, 181, tfoot))), ((Math.pow((1" ascii
    $s19 = "ofType)) & ((10 - eq) + (0 ^ always)))) - ((((546 | valHooks) / (59, rnamespace, 6, prefix)) & (3 * idx * 11 * computeStyleTests" ascii
    $s20 = "974) / computeStyleTests * 5 * idx), ((3 + left) - (137 + boxSizingReliable))), ((2 * computeStyleTests * 2 * removeAttr - 19 * " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}