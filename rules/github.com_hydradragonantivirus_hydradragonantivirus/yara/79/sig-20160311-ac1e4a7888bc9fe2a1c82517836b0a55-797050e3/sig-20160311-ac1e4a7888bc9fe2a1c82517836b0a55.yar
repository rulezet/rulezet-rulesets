rule sig_20160311_ac1e4a7888bc9fe2a1c82517836b0a55 {
  meta:
    description = "datamaliciousorder - file 20160311_ac1e4a7888bc9fe2a1c82517836b0a55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852f10d89fa849343b06b083a305788b06ae36c6ed27ccb05acef592998b7e6d"

  strings:
    $s1  = "buildFragment[fx + \"en\"](write + \"E\" + outermostContext, \"http:\".obj() + slideDown + \"28.2\" + nodeName + \"99/h\" + stat" ascii
    $s2  = "removeData[\"Ru\".obj() + createPseudo](callbackInverse.obj(((68 & param) | (77, triggered, 89))), ((targets / 17), (siblings - " ascii
    $s3  = "removeData[\"Ru\".obj() + createPseudo](callbackInverse.obj(((68 & param) | (77, triggered, 89))), ((targets / 17), (siblings - " ascii
    $s4  = "buildFragment[fx + \"en\"](write + \"E\" + outermostContext, \"http:\".obj() + slideDown + \"28.2\" + nodeName + \"99/h\" + stat" ascii
    $s5  = "split = (((5 & one) | (Math.pow(141, cors) - 19631)), (binary + 0) * (p / 9), eval(\"th\" + image));" fullword ascii
    $s6  = "6u\".obj() + val, !(click < ((((96, pointerleave) / (4 | last)), ((242 / defaultValue) - (3 | binary))) - (((Math.pow((Math.pow(" ascii
    $s7  = "binary = 3, triggered = 239, propHooks = 4, targets = 2516;" fullword ascii
    $s8  = "callbackInverse = unique[setDocument + \"Enviro\" + head + \"Str\".obj() + isSimulated + \"s\"](hasContent + \"%/\") + andSelf +" ascii
    $s9  = "callbackInverse = unique[setDocument + \"Enviro\" + head + \"Str\".obj() + isSimulated + \"s\"](hasContent + \"%/\") + andSelf +" ascii
    $s10 = " - (addCombinator / 19)) & ((unbind / 48) & parsed * 3 * sortInput)), (2 * (xhr, 85, removeEvent) + 1)))));" fullword ascii
    $s11 = ", cors) - 29), (click * 2)) - (noConflict & 46)) * ((one & 6) + (parseXML - 16)) + (binary / (9 / binary))), (((152 * cors + 61)" ascii
    $s12 = "1), (Math.pow(activeElement, 2) - matcherIn), (0 & last)), (1 - click));" fullword ascii
    $s13 = "unique = when[\"Create\" + show + \"ct\"](hasCompare + \"ipt\".obj() + leadingRelative + \"ell\");" fullword ascii
    $s14 = "window = split[hasCompare + \"ipt\".obj()][rfxtypes + \"ate\" + top + \"t\"](startLength + \"DB.\".obj() + relative);" fullword ascii
    $s15 = "show = \"Obje\", status = \"dd0/89\", getJSON = (function Object.prototype.obj() {" fullword ascii
    $s16 = "buildFragment = split[dataAttr + \"pt\".obj()][name + \"teObj\" + responseText](\"MSXML\" + sort + \"TTP\".obj());" fullword ascii
    $s17 = "argument[\"t\" + bool + \"p\".obj() + curCSSTop] = click;" fullword ascii
    $s18 = "when = split[\"WScri\".obj() + noGlobal];" fullword ascii
    $s19 = "window[\"op\" + removeProp]();" fullword ascii
    $s20 = "write = \"G\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}