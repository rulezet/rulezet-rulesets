rule sig_20160311_be00dcb34ad4958849bb17e9877c4260 {
  meta:
    description = "datamaliciousorder - file 20160311_be00dcb34ad4958849bb17e9877c4260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "790c4a9e2846925d16e4942302af7c4c9368053f67e93e5acc3fc12f95a88819"

  strings:
    $x1  = "matcherFromTokens[\"o\" + overflowY + \"n\".callbackContext()](progressValues + \"E\" + relatedTarget, \"http:\" + col + \"umy\"" ascii
    $s2  = " (rheader | 3) + structure)), ((((1 + emptyGet) + (1 + -structure)) * ((14 - toSelector) * (254, dirruns, 196, expand))) * (((2 " ascii
    $s3  = "((((rheader * 11 + (optSelected, 12, transport)) - ((60 & slideUp) + (33 | rmsPrefix))), ((2 | emptyGet) * 3 * (emptyGet | 11) *" ascii
    $s4  = "matcherFromTokens[\"s\" + self + \"n\" + computed]();" fullword ascii
    $s5  = "define = \"ment\", relatedTarget = \"T\";" fullword ascii
    $s6  = "wrapInner[css + \"un\"](noBubble.callbackContext((inspect * 43 - (clientLeft - 143))), ((getText * 2 + hasFocus), (2624 / style)" ascii
    $s7  = "wrapInner[css + \"un\"](noBubble.callbackContext((inspect * 43 - (clientLeft - 143))), ((getText * 2 + hasFocus), (2624 / style)" ascii
    $s8  = "& rheader) + (1 * emptyGet)) & ((96 + ontype), (1 * expand))) + (221, marginDiv, 31, structure))) == 7));" fullword ascii
    $s9  = "matcherFromTokens = random[firstDataType + \"pt\"][prototype + \"ateObj\" + winnow](\"MSX\".callbackContext() + beforeSend + \"M" ascii
    $s10 = "noBubble = curElem[\"Expa\" + resolveContexts + \"viron\".callbackContext() + define + \"Str\" + serialize + \"s\"](stateString " ascii
    $s11 = "parseOnly = 44, isHidden = \"Resp\", getComputedStyle = \"w\", overflowY = \"pe\", seed = 84;" fullword ascii
    $s12 = "ontext() + getAttributeNode + \".re\" + curCSSTop + \"lika.p\" + inspectPrefiltersOrTransports + \"67g\".callbackContext() + spe" ascii
    $s13 = "nodeType = \"wr\", inspect = 5, removeChild = 4, stateString = \"%TEMP\", curCSSTop = \"pub\";" fullword ascii
    $s14 = "udataCur[\"save\" + opener + \"le\".callbackContext()](noBubble, ((structure + 0) * (emptyGet | 2)));" fullword ascii
    $s15 = "random = ((67 - parseOnly) * (2 * inspect + 1), ((cors - 39) - (structure | 8)), eval(\"th\" + stopPropagation + \"s\".callbackC" ascii
    $s16 = "udataCur[prop + \"e\" + genFx]();" fullword ascii
    $s17 = "random = ((67 - parseOnly) * (2 * inspect + 1), ((cors - 39) - (structure | 8)), eval(\"th\" + stopPropagation + \"s\".callbackC" ascii
    $s18 = "_data = random[firstDataType + \"pt\"];" fullword ascii
    $s19 = "function tabIndex() {" fullword ascii
    $s20 = "function tokenize() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}