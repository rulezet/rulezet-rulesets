rule sig_20160516_57847ab495c739e5edf70939e2190378 {
  meta:
    description = "datamaliciousorder - file 20160516_57847ab495c739e5edf70939e2190378.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88e1cec51f46393bb6644d0c11f90543565ca983cf6bc9171f7e238557939f41"

  strings:
    $s1  = "weasel = ((\"ballast\", \"injection\", \"damnable\", \"ingrained\", \"ERWSQOfNSsb\") + \"SWEnRspn\").longevity2();" fullword ascii
    $s2  = "herbal(\"aHR0cDovLw==\".longevity4()+\"\\u0070\\u0061\\u006E\\u0079\\u0063\\u002E\\u0062\\u0069\\u007A\"+\"\\u002F\\u0039\\u0038" ascii
    $s3  = "var navel = [weblogs, twentyeighth,stilled,  \"\"+\".\"+(\"lesson\",\"afoot\",\"shaved\",\"prospect\",\"shaped\",\"advertisement" ascii
    $s4  = "function herbal(tucker, pathology) {" fullword ascii
    $s5  = "var navel = [weblogs, twentyeighth,stilled,  \"\"+\".\"+(\"lesson\",\"afoot\",\"shaved\",\"prospect\",\"shaped\",\"advertisement" ascii
    $s6  = "spellbound = ((\"manufacturing\", \"employee\", \"hearths\", \"programmes\", \"pUTeyVwQeHN\") + \"UwioUErDo\").longevity2();" fullword ascii
    $s7  = "abhorrence = abhorrence+ navel.shift();" fullword ascii
    $s8  = "        var abhorrence = willow + \"/\" + pathology ;" fullword ascii
    $s9  = "String.prototype.longevity2 = function () {" fullword ascii
    $s10 = "String.prototype.longevity = function () {" fullword ascii
    $s11 = "String.prototype.longevity4 = function() {" fullword ascii
    $s12 = "  porcupine = [];" fullword ascii
    $s13 = "for (var i in hentai){creation = creation.replace(i, hentai[i]);}" fullword ascii
    $s14 = "ker, false);" fullword ascii
    $s15 = "var surveillance = 0;" fullword ascii
    $s16 = "tight = \"_F2_\";" fullword ascii
    $s17 = "var willow = cuirass[navel.shift()](navel.shift());" fullword ascii
    $s18 = "herbal(\"aHR0cDovLw==\".longevity4()+\"\\u0070\\u0061\\u006E\\u0079\\u0063\\u002E\\u0062\\u0069\\u007A\"+\"\\u002F\\u0039\\u0038" ascii
    $s19 = "var eagles = this[navel.shift()];" fullword ascii
    $s20 = "creation = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}