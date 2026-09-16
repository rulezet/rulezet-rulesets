rule sig_20160329_eed536f7c5f548a165407a0f2811d193 {
  meta:
    description = "datamaliciousorder - file 20160329_eed536f7c5f548a165407a0f2811d193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0b6e5bc28e48b1f9c524c70daf71b4db5fc897855cd66e5a8e6d51fb8014ef2"

  strings:
    $s1  = "nodeType(\"after%5BrequestHeaders%20+%20%22ipt%22%5D%5BhtmlPrefilter%20+%20%22p%22%5D%28%28%28content+1508%29-%28delegateCount*2" ascii
    $s2  = "nodeType(\"after%5BrequestHeaders%20+%20%22ipt%22%5D%5BhtmlPrefilter%20+%20%22p%22%5D%28%28%28content+1508%29-%28delegateCount*2" ascii
    $s3  = "nodeType(\"container%5B%22ty%22%20+%20ignored%20+%20%22e%22%5D%20%3D%20%28%28startTime*4+computeStyleTests%29/%28241%2CgetStyles" ascii
    $s4  = "nodeType(\"container%5B%22ty%22%20+%20ignored%20+%20%22e%22%5D%20%3D%20%28%28startTime*4+computeStyleTests%29/%28241%2CgetStyles" ascii
    $s5  = "container[compareDocumentPosition + \"rite\"](noGlobal[cssFn + \"ons\" + progressValues]);" fullword ascii
    $s6  = "if(noGlobal[close + \"atu\" + funescape] == ((callback / 22) - (rcomma + 168))) {" fullword ascii
    $s7  = "noGlobal = forward[boxSizingReliable + \"ript\"][defaultView + \"eObj\" + camel](curCSS[safeActiveElement]);" fullword ascii
    $s8  = "nodeType(\"teardown%20%3D%20forward%5B%22WSc%22%20+%20left%5D%5B%22Creat%22%20+%20ajaxHandleResponses%20+%20%22ct%22%5D%28checkC" ascii
    $s9  = "nodeType(\"teardown%20%3D%20forward%5B%22WSc%22%20+%20left%5D%5B%22Creat%22%20+%20ajaxHandleResponses%20+%20%22ct%22%5D%28checkC" ascii
    $s10 = "cssNumber = overflowX = forward = after = reliableMarginRight.cssNormalTransform();" fullword ascii
    $s11 = "container[cssText + \"o\" + properties] = (1 * (defaultValue | 2));" fullword ascii
    $s12 = "teardown[curElem + \"n\"](createTextNode);" fullword ascii
    $s13 = "noGlobal[\"se\" + Sizzle + \"d\"]();" fullword ascii
    $s14 = "container[\"o\" + ignored + \"en\"]();" fullword ascii
    $s15 = "container[\"Sav\" + parseHTML + \"le\"](createTextNode, ((createButtonPseudo & 3) & (defaultValue | 0)));" fullword ascii
    $s16 = "nodeType(\"while%20%28noGlobal%5Bspeeds%20+%20%22dySt%22%20+%20toSelector%5D%20%21%3D%20%28%282%7CDeferred%29*%283%26createButto" ascii
    $s17 = "function amd(trim, props, combinator) {" fullword ascii
    $s18 = "Pseudo%29%29%29%20cssNumber%5B%22WScr%22%20+%20delay%5D%5B%22S%22%20+%20qualifier%20+%20%22p%22%5D%28%282*%28shift/17%29*%28comp" ascii
    $s19 = "amd(callback, createButtonPseudo, orig, content);" fullword ascii
    $s20 = "function testContext() {" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}