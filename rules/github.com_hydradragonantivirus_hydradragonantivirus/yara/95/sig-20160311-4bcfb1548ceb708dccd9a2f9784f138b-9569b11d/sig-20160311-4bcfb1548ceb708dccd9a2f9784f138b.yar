rule sig_20160311_4bcfb1548ceb708dccd9a2f9784f138b {
  meta:
    description = "datamaliciousorder - file 20160311_4bcfb1548ceb708dccd9a2f9784f138b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a3d365f4bf289abbc6fde7a5c840e059028b41189c53266353883da93284b0"

  strings:
    $x1  = "parentOffset[stopPropagation + \"e\" + XMLHttpRequest](\"GE\" + pushStack, \"http:\".tweens() + siblingCheck + \"momsta\" + node" ascii
    $s2  = "responseFields = addGetHookIf[\"Expan\" + value + \"ron\".tweens() + rcleanScript + \"Strin\" + Sizzle](\"%TEMP\" + contains) + " ascii
    $s3  = "responseFields = addGetHookIf[\"Expan\" + value + \"ron\".tweens() + rcleanScript + \"Strin\" + Sizzle](\"%TEMP\" + contains) + " ascii
    $s4  = "wrapMap[unmatched + \"un\".tweens()](responseFields.tweens(((processData & 93) & (size & 127))), ((current | 1) + -(elem - 34))," ascii
    $s5  = "wrapMap[unmatched + \"un\".tweens()](responseFields.tweens(((processData & 93) & (size & 127))), ((current | 1) + -(elem - 34))," ascii
    $s6  = "| overflow), (47 * keepScripts)), (Math.pow((10 * markFunction + 2), (clientX * 2)) - (checkOn + 9270)), ((then, 209, vendorProp" ascii
    $s7  = "ies) | (0 | properties))))) == ((((179, compiled, 201, propFix) - 136), ((Math.pow(extend, 2) - fadeIn), (2568 / tweeners), (68 " ascii
    $s8  = " properties * 3 * keepScripts), ((3 + original) * (42 - when) + ((3 * err) | (19 - qualifier))), ((1 * (pageY - 10)) & ((propert" ascii
    $s9  = "m/0\" + finalText + \"67\".tweens(), !((((((96 - suffix) - (40 | requestHeadersNames)) & ((55 - PI) + 0)) & ((current | 2) * (PI" ascii
    $s10 = "- (642 - compare)))))));" fullword ascii
    $s11 = "Name, 36) - (source, 173, mouseHooks))) * ((42 - image) + (2 + (vendorPropName & 15))), ((Math.pow((clientY / 27), (clientX * 2)" ascii
    $s12 = "addGetHookIf = rejectWith[rbuggyMatches + \"ateOb\" + replaceChild + \"t\".tweens()](nextSibling + \"t.S\" + bool);" fullword ascii
    $s13 = "48) & ((current | 0) | (err | 6)))) | (((response / 4), (compare + 160), (_data - 52)) * ((nodeNameSelector, 250, rclass) - (1 +" ascii
    $s14 = "function rscriptTypeMasked() {" fullword ascii
    $s15 = "function postFilter() {" fullword ascii
    $s16 = "status[defaultDisplay + \"e\".tweens()]();" fullword ascii
    $s17 = "current / (8 * err + 3)));" fullword ascii
    $s18 = "originalSettings = showHide[\"WScr\" + isTrigger][\"Crea\".tweens() + pseudos + \"bje\" + xhr](\"ADO\" + time + \"eam\".tweens()" ascii
    $s19 = "current = 0;" fullword ascii
    $s20 = "qualifier = 15;" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    1 of ($x*) and 4 of them
}