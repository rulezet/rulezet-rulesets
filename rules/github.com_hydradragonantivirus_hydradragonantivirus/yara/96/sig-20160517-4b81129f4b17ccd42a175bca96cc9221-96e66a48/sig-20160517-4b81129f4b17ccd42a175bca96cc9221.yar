rule sig_20160517_4b81129f4b17ccd42a175bca96cc9221 {
  meta:
    description = "datamaliciousorder - file 20160517_4b81129f4b17ccd42a175bca96cc9221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b6569ce521e98303c663376f6e17558ea24acc35542dab40f9ef3c28b612039"

  strings:
    $s1  = "var willow=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".dinghy4())&&sacristan[\"c3RhdHVz\".dinghy4()] +\"\"==\"MjAw\".dinghy4" ascii
    $s2  = "var willow=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".dinghy4())&&sacristan[\"c3RhdHVz\".dinghy4()] +\"\"==\"MjAw\".dinghy4" ascii
    $s3  = "function dialog(against, steaming) {" fullword ascii
    $s4  = "        armoury[(dauntless + \"o\"+(\"homemade\",\"tenet\",\"courtship\",\"winnings\",\"queen\",\"baldness\",\"pennon\",\"theolo" ascii
    $s5  = "String.prototype.dinghy = function () {" fullword ascii
    $s6  = "String.prototype.dinghy4 = function() {" fullword ascii
    $s7  = "var comeliness = \"QWN0displayaXZlWE9idisplayamVjdA==display\".dinghy4();" fullword ascii
    $s8  = "String.prototype.dinghy2 = function () {" fullword ascii
    $s9  = "\"s\")+\"ubRt\"+(\"decrease\",\"running\",\"harried\",\"latch\",\"reproduced\",\"bureau\",\"johnson\",\"ri\")+\"ng\").replace(\"" ascii
    $s10 = "var finland = plants.pop().split(\"" fullword ascii
    $s11 = "vizier = \"b3Blbg==\".dinghy4();;" fullword ascii
    $s12 = "var seraphic = this[plants.shift()];" fullword ascii
    $s13 = "        armoury[(dauntless + \"o\"+(\"homemade\",\"tenet\",\"courtship\",\"winnings\",\"queen\",\"baldness\",\"pennon\",\"theolo" ascii
    $s14 = "  tragedy = [];" fullword ascii
    $s15 = "var expanding = {" fullword ascii
    $s16 = "var learned =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".dinghy4();" fullword ascii
    $s17 = "var shant = 0;" fullword ascii
    $s18 = "weasel = ((\"calculators\", \"foreground\", \"fireplace\", \"thinks\", \"ESOWCKyBH\") + \"nebWsDFSRI\").dinghy2();" fullword ascii
    $s19 = "dauntless = ((\"innovations\", \"zephyr\", \"bedroom\", \"capability\", \"ppmMjKmXiSWL\") + \"tnodQyJHv\").dinghy2();" fullword ascii
    $s20 = "gainst, false);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}