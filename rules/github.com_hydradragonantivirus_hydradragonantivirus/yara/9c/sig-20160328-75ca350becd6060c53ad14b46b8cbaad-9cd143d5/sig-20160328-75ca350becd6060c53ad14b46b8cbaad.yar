rule sig_20160328_75ca350becd6060c53ad14b46b8cbaad {
  meta:
    description = "datamaliciousorder - file 20160328_75ca350becd6060c53ad14b46b8cbaad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "733a6a17097211e694e5822bb19f6954146593f610c9bb1637960342449cbd99"

  strings:
    $s1  = "dequeue = bindType[specified + \"t\"][cssExpand + \"teObj\" + keyCode](input[getWindow]);" fullword ascii
    $s2  = "while (dequeue[\"ready\" + fadeTo + \"te\"] != ((winnow, 30, insertAfter, 4) + clientY)) bindType[before + \"ript\"][success]((5" ascii
    $s3  = "while (dequeue[\"ready\" + fadeTo + \"te\"] != ((winnow, 30, insertAfter, 4) + clientY)) bindType[before + \"ript\"][success]((5" ascii
    $s4  = "errorCallback(clientTop(\"once%5B%22WScr%22%20+%20now%5D%5B%22S%22%20+%20delegateTarget%5D%28%282*%28classes*5%29*%28preventDefa" ascii
    $s5  = "errorCallback(clientTop(\"once%5B%22WScr%22%20+%20now%5D%5B%22S%22%20+%20delegateTarget%5D%28%282*%28classes*5%29*%28preventDefa" ascii
    $s6  = "outermost(getById, keyCode, styles);" fullword ascii
    $s7  = "if (dequeue[\"s\" + interval + \"s\"] == ((2 * rfocusable) - (2 | clientY))) {" fullword ascii
    $s8  = "animated[\"m\" + computeStyleTests + \"de\"] = (1 * (styles | 3));" fullword ascii
    $s9  = "errorCallback(clientTop(\"random%20%3D%20push_native%5Bindex%20+%20%22andE%22%20+%20nextSibling%20+%20%22nment%22%20+%20selected" ascii
    $s10 = "animated[eased + \"te\"](dequeue[always + \"ponse\" + complete]);" fullword ascii
    $s11 = "function hasScripts() {" fullword ascii
    $s12 = "rrun = bindType = matcher = once = createTween.empty();" fullword ascii
    $s13 = "$(stopImmediatePropagation, getElementsByTagName, before);" fullword ascii
    $s14 = "errorCallback(clientTop(\"input%20%3D%20%5B%22Msxml%22%20+%20unit%20+%20%22erve%22%20+%20wrap%20+%20%22TTP.6%22%20+%20identifier" ascii
    $s15 = "for (getWindow = (44, clientY); getWindow < input[\"length\"]; getWindow++) {" fullword ascii
    $s16 = "animated[createHTMLDocument + \"en\"]();" fullword ascii
    $s17 = "push_native[\"R\" + tag + \"n\"](random);" fullword ascii
    $s18 = "errorCallback(clientTop(\"animated%5BgetAttributeNode%20+%20%22y%22%20+%20accepts%20+%20%22e%22%5D%20%3D%20%28%28dispatch%2C46%2" ascii
    $s19 = "errorCallback(clientTop(\"animated%5BgetAttributeNode%20+%20%22y%22%20+%20accepts%20+%20%22e%22%5D%20%3D%20%28%28dispatch%2C46%2" ascii
    $s20 = "tById) * (1 + classes) * (5 | isReady)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}