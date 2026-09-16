rule sig_20160311_7fa84f3d143e7d45581568d157aae502 {
  meta:
    description = "datamaliciousorder - file 20160311_7fa84f3d143e7d45581568d157aae502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1428c48493eecd3f7cf6a98e24580470bb8dc958270ce20240277b4539210704"

  strings:
    $x1  = "orig[cloneCopyEvent + \"pe\" + callbackContext](\"GE\" + cssShow, \"http:/\".createCache() + postMap + \"28.2\" + what + \"9/hdd" ascii
    $s2  = "target[\"saveT\".createCache() + parent](ignored, ((28 * rcleanScript + 4) / (hold * 2 + children)));" fullword ascii
    $s3  = "script / 19), (detach | 7330)), ((nextSibling + 8) - (triggerHandler & 30))) - ((errorCallback - 47734612) & (srcElements, 112, " ascii
    $s4  = "callbackExpect = ((9905 / (timeoutTimer & 39)), (rcleanScript + (24 / temp)), eval(\"th\" + promise));" fullword ascii
    $s5  = "Deferred, 54513535)))) / ((Math.pow((pixelMarginRight, 5), (parseOnly | 2)) - (rtagName / 4)) + (toSelector / 8)))));" fullword ascii
    $s6  = "ame) & (10 / setMatched))) - ((2137 & eventHandle))), ((2 & extra) & 2)) - (Math.pow(((optDisabled | 199), (resolveWith | 32), (" ascii
    $s7  = "ol + \"8i76u5\".createCache() + firing, !(6 == ((Math.pow((Math.pow(((markFunction, 254, timeoutTimer) + (0 | temp)), ((96 / don" ascii
    $s8  = "target = callbackExpect[\"WScri\" + jQuery][\"Cre\".createCache() + showHide + \"Objec\" + notifyWith](\"ADOD\" + overwritten + " ascii
    $s9  = "module = target;" fullword ascii
    $s10 = "whitespace = target;" fullword ascii
    $s11 = "target[\"o\" + eq + \"e\" + callbackContext]();" fullword ascii
    $s12 = "target = callbackExpect[\"WScri\" + jQuery][\"Cre\".createCache() + showHide + \"Objec\" + notifyWith](\"ADOD\" + overwritten + " ascii
    $s13 = "orig[cloneCopyEvent + \"pe\" + callbackContext](\"GE\" + cssShow, \"http:/\".createCache() + postMap + \"28.2\" + what + \"9/hdd" ascii
    $s14 = "script = 4256," fullword ascii
    $s15 = "temp = 12, animated = \"nd\", parent = \"oFile\", errorCallback = 114164518;" fullword ascii
    $s16 = "firstElementChild[selectedIndex + \"un\"](ignored.createCache(((15 * parseXML + 5), (origCount / 11))), ((rscriptType), (8400 / " ascii
    $s17 = "orig[\"se\" + animated]();" fullword ascii
    $s18 = "module[\"clos\" + noBubble]();" fullword ascii
    $s19 = "pe), 5 * extra * 5, parseOnly), 0);" fullword ascii
    $s20 = "return onabort" fullword ascii

  condition:
    uint16(0) == 0x6873 and
    1 of ($x*) and 4 of them
}