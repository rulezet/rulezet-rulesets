rule sig_20160516_4ed3ec75d6944e092dd0a36744408197 {
  meta:
    description = "datamaliciousorder - file 20160516_4ed3ec75d6944e092dd0a36744408197.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abc131f3f386fae278091a96cf1452edb7b6b96d068d79e05d9e590b288b6364"

  strings:
    $s1  = "treadmill = ((\"times\", \"specialist\", \"elliott\", \"goblin\", \"pzPgLHrmomf\") + \"uehEWXtw\").civilian2();" fullword ascii
    $s2  = "var graduate=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".civilian4())&&laddie[\"c3RhdHVz\".civilian4()] +\"\"==\"MjAw\".civi" ascii
    $s3  = "var graduate=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".civilian4())&&laddie[\"c3RhdHVz\".civilian4()] +\"\"==\"MjAw\".civi" ascii
    $s4  = "var nowhere = [degrees, sticky,albanian,  \"\"+\".\"+(\"lineage\",\"circuits\",\"fruits\",\"muscle\",\"affecting\",\"stability\"" ascii
    $s5  = "var nowhere = [degrees, sticky,albanian,  \"\"+\".\"+(\"lineage\",\"circuits\",\"fruits\",\"muscle\",\"affecting\",\"stability\"" ascii
    $s6  = "weasel = ((\"enumeration\", \"dogmatic\", \"professionals\", \"punctilious\", \"EPiYyKPn\") + \"uWBXYSY\").civilian2();" fullword ascii
    $s7  = "petroleum = petroleum+ nowhere.shift();" fullword ascii
    $s8  = "sewing = ((\"pentecost\", \"forsook\", \"crossword\", \"manoeuvring\", \"sDsypDIRAy\") + \"PWxCjFdYxXi\").civilian2();" fullword ascii
    $s9  = "aggrandizement(\"aHR0cDovLw==\".civilian4()+\"\\u0064\\u0069\\u0067\\u0061\\u0073\\u0069\\u0062\\u002E\\u0063\\u006F\"+\"\\u006D" ascii
    $s10 = "juxtaposition[nowhere.shift()](petroleum, commissions, true);dGEmUsGYaGz = \"_F17_\";" fullword ascii
    $s11 = "var failed = juxtaposition[nowhere.shift()](nowhere.shift());" fullword ascii
    $s12 = "String.prototype.civilian4 = function() {" fullword ascii
    $s13 = "String.prototype.civilian = function () {" fullword ascii
    $s14 = "String.prototype.civilian2 = function () {" fullword ascii
    $s15 = "        recycling[(treadmill + \"o\"+(\"consecration\",\"settle\",\"padlock\",\"loyally\",\"insecure\",\"foundation\",\"seminary" ascii
    $s16 = "        var petroleum = failed + \"/\" + accepted ;" fullword ascii
    $s17 = "        recycling[(\"years\",\"spherical\",\"soccer\",\"buckle\",\"ideal\",\"preview\",\"autograph\",\"w\")+\"ri\"+\"te\"](laddi" ascii
    $s18 = "t, false);" fullword ascii
    $s19 = "lie\",\"humbug\",\"greek\",\"slayer\",\"wearer\",\"outermost\",\"leguminous\",\"deputation\",\"SEOO\")+\"DB\"+(\"received\",\"ta" ascii
    $s20 = "var juxtaposition = new purse(milfhunter[1]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}