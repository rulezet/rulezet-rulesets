rule sig_20160516_7b693780c6a59f0457afdda8a4ae4869 {
  meta:
    description = "datamaliciousorder - file 20160516_7b693780c6a59f0457afdda8a4ae4869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89926ecd4def5e6089950d144806cc36410ced9b15bdcfa5685bece5e052713a"

  strings:
    $s1  = "weasel = ((\"colossus\", \"circle\", \"nourishing\", \"bevis\", \"ElggDEcEp\") + \"PLbWriDWsTS\").ludwig2();" fullword ascii
    $s2  = "var virulent=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".ludwig4())&&jefferson[\"c3RhdHVz\".ludwig4()] +\"\"==\"MjAw\".ludwi" ascii
    $s3  = "proven = ((\"deemed\", \"whack\", \"woodsman\", \"lithuania\", \"pggMMXqO\") + \"wXkosgQyFdv\").ludwig2();" fullword ascii
    $s4  = "pulsation(\"aHR0cDovLw==\".ludwig4()+\"\\u0062\\u0065\\u006C\\u0075\\u0078\\u0066\\u0075\\u0072\\u006E\\u0069\\u0074\\u0075\\u00" ascii
    $s5  = "theorist = ((\"returns\", \"promises\", \"aluminium\", \"tradesman\", \"sijMmWjTDPp\") + \"ElNPWHSc\").ludwig2();" fullword ascii
    $s6  = "mutter = mutter+ bounteous.shift();" fullword ascii
    $s7  = "String.prototype.ludwig = function () {" fullword ascii
    $s8  = "String.prototype.ludwig4 = function() {" fullword ascii
    $s9  = "String.prototype.ludwig2 = function () {" fullword ascii
    $s10 = "var bounteous = [staying, wealth,mexico,  \"\"+\".\"+(\"saltpetre\",\"myspace\",\"comic\",\"moisture\",\"friendly\",\"servers\"," ascii
    $s11 = "            jefferson[hints]((\"acrimony\",\"ideas\",\"G\" + weasel) + (\"abscess\",\"concomitant\",\"organizing\",\"managing\"," ascii
    $s12 = "            jefferson[hints]((\"acrimony\",\"ideas\",\"G\" + weasel) + (\"abscess\",\"concomitant\",\"organizing\",\"managing\"," ascii
    $s13 = "} catch (aLOgYw) { };" fullword ascii
    $s14 = "piquant = \"_F2_\";" fullword ascii
    $s15 = "bilateral[bounteous.shift()](mutter, functional, true);RePEyCsLDmK = \"_F17_\";" fullword ascii
    $s16 = "lumina\",\"skinny\",\"wordy\",\"aurora\",\"extras\",\"08\"), theorist)] = 0;" fullword ascii
    $s17 = "soviet = this;" fullword ascii
    $s18 = "function pulsation(diving, wreak) {" fullword ascii
    $s19 = "    if ( circuits[ i ] === undefined )" fullword ascii
    $s20 = "var functional = 6/6;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}