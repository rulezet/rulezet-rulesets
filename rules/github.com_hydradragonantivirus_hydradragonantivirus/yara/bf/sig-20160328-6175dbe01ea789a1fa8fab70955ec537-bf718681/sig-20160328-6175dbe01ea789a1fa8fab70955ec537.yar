rule sig_20160328_6175dbe01ea789a1fa8fab70955ec537 {
  meta:
    description = "datamaliciousorder - file 20160328_6175dbe01ea789a1fa8fab70955ec537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5205671a831f565a528061aef99b8296aa314c18567bebf31b0882755720264"

  strings:
    $x1  = "eval(reset(\"results%20%3D%20%28%222.XM%22%29%3BcontentDocument%20%3D%20%28161%29%3Bvar%20parse%20%3D%20%28%22truc%22%29%2C%20sw" ascii
    $s2  = "for(forward = (1 + -marginRight); forward < reject[\"length\"]; forward++) {" fullword ascii
    $s3  = "cssFn[getStyles + \"ipt\"][fragment + \"p\"](((19575 / e) - (2127 - createInputPseudo)));" fullword ascii
    $s4  = "letter[\"t\" + getResponseHeader + \"e\"] = ((1 & marginRight) & (39 - errorCallback));" fullword ascii
    $s5  = "letter[rsubmittable + \"ToFile\"](augmentWidthOrHeight, ((contentDocument - 74), (slow * 2 + bySet), (2 | classNames)));" fullword ascii
    $s6  = "getPropertyValue[\"WScrip\" + assert][\"Sleep\"](((pdataCur / 43) & (method & 8075)));" fullword ascii
    $s7  = "letter[\"Write\"](copyIsArray[xml + \"nseBod\" + addToPrefiltersOrTransports]);" fullword ascii
    $s8  = "getElementsByClassName(reset(\"copyIsArray%5BstateVal%20+%20%22p%22%20+%20Sizzle%20+%20%22n%22%5D%28trigger%20+%20%22T%22%2C%20r" ascii
    $s9  = "getElementsByClassName(reset(\"copyIsArray%20%3D%20cssFn%5Buid%20+%20%22rip%22%20+%20assert%5D%5B%22Crea%22%20+%20_%24%20+%20%22" ascii
    $s10 = "high(results, unbind, addToPrefiltersOrTransports);" fullword ascii
    $s11 = "eval(reset(\"results%20%3D%20%28%222.XM%22%29%3BcontentDocument%20%3D%20%28161%29%3Bvar%20parse%20%3D%20%28%22truc%22%29%2C%20sw" ascii
    $s12 = "while(copyIsArray[\"rea\" + oldCache + \"ate\"] != ((classNames * 2) + (marginRight * 0))) getPropertyValue[getStyles + \"ipt\"]" ascii
    $s13 = "while(copyIsArray[\"rea\" + oldCache + \"ate\"] != ((classNames * 2) + (marginRight * 0))) getPropertyValue[getStyles + \"ipt\"]" ascii
    $s14 = "getElementsByClassName(reset(\"reject%20%3D%20%5BgetById%20+%20%222.Se%22%20+%20round%20+%20%22rXMLHT%22%20+%20fired%2C%20%22Msx" ascii
    $s15 = "ent + \"p\"](((elementMatchers | 1) + (swing + 10)));" fullword ascii
    $s16 = "getElementsByClassName(reset(\"configurable%28removeProp%20+%20%22p%3A//po%22%20+%20dataAttr%20+%20%22-da%22%20+%20setMatched%20" ascii
    $s17 = "getElementsByClassName(reset(\"configurable%28removeProp%20+%20%22p%3A//po%22%20+%20dataAttr%20+%20%22-da%22%20+%20setMatched%20" ascii
    $s18 = "getElementsByClassName(reset(\"letter%20%3D%20getPropertyValue%5B%22WSc%22%20+%20pageYOffset%5D%5B%22Creat%22%20+%20access%20+%2" ascii
    $s19 = "letter[\"mo\" + v] = (3 | marginRight);" fullword ascii
    $s20 = "letter[\"op\" + pixelMarginRight]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}