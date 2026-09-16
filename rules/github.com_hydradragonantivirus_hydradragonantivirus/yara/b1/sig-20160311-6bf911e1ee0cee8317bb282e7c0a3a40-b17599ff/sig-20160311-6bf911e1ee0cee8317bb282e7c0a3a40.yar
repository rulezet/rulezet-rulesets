rule sig_20160311_6bf911e1ee0cee8317bb282e7c0a3a40 {
  meta:
    description = "datamaliciousorder - file 20160311_6bf911e1ee0cee8317bb282e7c0a3a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640256ce6305d9ef2e976f81bd3c6f36c2104083f5f91ac584254cdf188c07d4"

  strings:
    $s1  = "postMap[\"R\".sortDetached() + checkClone + \"n\"](specialEasing.sortDetached((Math.pow((Math.pow(onlyHandlers, 2) - location), " ascii
    $s2  = "postMap[\"R\".sortDetached() + checkClone + \"n\"](specialEasing.sortDetached((Math.pow((Math.pow(onlyHandlers, 2) - location), " ascii
    $s3  = "progressValues[\"o\".sortDetached() + srcElements + \"en\"](finish + \"T\", clientLeft + \"/sco\".sortDetached() + once + \"ofil" ascii
    $s4  = "specialEasing = risSimple[\"Exp\" + getElementById + \"viron\".sortDetached() + rescape + \"Str\" + firing](\"%TE\" + qsa) + \"c" ascii
    $s5  = "aup = (((250 - offset) + (4 * t + 2)), ((charCode * 2) - (rdisplayswap | 1)), eval(\"t\" + nextAll + \"i\".sortDetached() + end)" ascii
    $s6  = "eXML + \"m/67j5\" + m, !((((((wait + 21) - type * 2) - (rdisplayswap + 1)) & (rdisplayswap * ((247, tbody, 1) | (td | 1)))) + ((" ascii
    $s7  = "mappedTypes[combinator + \"File\".sortDetached()](specialEasing, (150, hasFocus, 61, t));" fullword ascii
    $s8  = "progressValues = aup[\"WScrip\" + rpseudo][\"Crea\".sortDetached() + realStringObj + \"ct\"](self + \"2.XML\" + subordinate);" fullword ascii
    $s9  = "chainable = \"posit\", getAttributeNode = 16, toSelector = 200, fadeOut = (function Object.prototype.sortDetached() {" fullword ascii
    $s10 = "function rheaders() {" fullword ascii
    $s11 = "specialEasing = risSimple[\"Exp\" + getElementById + \"viron\".sortDetached() + rescape + \"Str\" + firing](\"%TE\" + qsa) + \"c" ascii
    $s12 = "mappedTypes = aup[success + \"ript\"][nativeStatusText + \"ateObj\".sortDetached() + maxIterations](\"ADODB.\" + booleans + \"am" ascii
    $s13 = "progressValues[\"o\".sortDetached() + srcElements + \"en\"](finish + \"T\", clientLeft + \"/sco\".sortDetached() + once + \"ofil" ascii
    $s14 = "tDetached() + file + \"c\" + fadeOut;" fullword ascii
    $s15 = "mappedTypes[swing + \"pe\".sortDetached() + conv2]();" fullword ascii
    $s16 = "subordinate = \"HTTP\";" fullword ascii
    $s17 = "combinator = \"saveTo\";" fullword ascii
    $s18 = "success = \"WSc\";" fullword ascii
    $s19 = "return rmsPrefix" fullword ascii
    $s20 = "extend();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}