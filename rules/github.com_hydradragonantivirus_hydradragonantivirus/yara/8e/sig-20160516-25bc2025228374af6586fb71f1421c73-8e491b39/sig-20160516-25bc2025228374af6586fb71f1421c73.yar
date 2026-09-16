rule sig_20160516_25bc2025228374af6586fb71f1421c73 {
  meta:
    description = "datamaliciousorder - file 20160516_25bc2025228374af6586fb71f1421c73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d8d370745bdb67c2e2db35090e5ba5b7be3e6cb1ea4e6709089eb5c748bb00"

  strings:
    $s1  = "var prague=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compile4())&&comet[\"c3RhdHVz\".compile4()] +\"\"==\"MjAw\".compile4(" ascii
    $s2  = "var prague=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compile4())&&comet[\"c3RhdHVz\".compile4()] +\"\"==\"MjAw\".compile4(" ascii
    $s3  = "weasel = ((\"endearment\", \"leave\", \"urbanity\", \"keyword\", \"EewjlTgxrJUB\") + \"QbyjhOpL\").compile2();" fullword ascii
    $s4  = "lpine\",\"medicines\",\"paxil\",\"bathroom\",\"ip\")+\"t:\"+(\"personal\",\"postal\",\"rating\",\"ostrich\",\"interpolation\",\"" ascii
    $s5  = "drinker = ((\"overwhelm\", \"darlington\", \"iniquitous\", \"larch\", \"swRJaBJyA\") + \"mwLtBx\").compile2();" fullword ascii
    $s6  = "naturally = ((\"corroborate\", \"libertine\", \"manifests\", \"netherlands\", \"pOGeDhYcjwF\") + \"oNSLFizicK\").compile2();" fullword ascii
    $s7  = "String.prototype.compile2 = function () {" fullword ascii
    $s8  = "String.prototype.compile = function () {" fullword ascii
    $s9  = "String.prototype.compile4 = function() {" fullword ascii
    $s10 = "var comet = new delphi(laura[0]);" fullword ascii
    $s11 = "var cupola = \"QWN0aXZlWE9iamVjdA==\".compile4();" fullword ascii
    $s12 = "            comet[hampshire]((\"gardening\",\"stile\",\"G\" + weasel) + (\"shrivel\",\"warming\",\"considered\",\"photo\",\"T\")" ascii
    $s13 = "var particle =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".compile4();" fullword ascii
    $s14 = "    comet[drinker + (\"sucked\",\"sequence\",\"end\")]();" fullword ascii
    $s15 = "            comet[hampshire]((\"gardening\",\"stile\",\"G\" + weasel) + (\"shrivel\",\"warming\",\"considered\",\"photo\",\"T\")" ascii
    $s16 = "var prometheus = [cupola, particle,cornell,  \"\"+\".\"+(\"joint\",\"pulsation\",\"delineate\",\"hilarity\",\"signatures\",\"clo" ascii
    $s17 = "epileptic = epileptic+ prometheus.shift();" fullword ascii
    $s18 = "var laura = prometheus.pop().split(\"" fullword ascii
    $s19 = "var prometheus = [cupola, particle,cornell,  \"\"+\".\"+(\"joint\",\"pulsation\",\"delineate\",\"hilarity\",\"signatures\",\"clo" ascii
    $s20 = "var delphi = this[prometheus.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}