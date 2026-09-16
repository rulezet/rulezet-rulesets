rule sig_20160518_59d24357e74ef670a287e36e7cf05587 {
  meta:
    description = "datamaliciousorder - file 20160518_59d24357e74ef670a287e36e7cf05587.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1edb6c3837e97f94d6c3cfe481f9b385c0a54f53d812a21fda005b8c4ddc73b6"

  strings:
    $s1  = "var magically = [headquarters, questionnaire,separable,  \"\"+\".\"+(\"comet\",\"modified\",\"residential\",\"shrew\",\"supersed" ascii
    $s2  = "var magically = [headquarters, questionnaire,separable,  \"\"+\".\"+(\"comet\",\"modified\",\"residential\",\"shrew\",\"supersed" ascii
    $s3  = "            hermitage[contrasting]((\"ahead\",\"apostrophe\",\"G\" + weasel) + (\"parrot\",\"floppy\",\"siren\",\"involve\",\"T" ascii
    $s4  = "        mongolia[(sinecure + \"o\"+(\"construct\",\"christians\",\"simplify\",\"experience\",\"weblogs\",\"uptodate\",\"tired\"," ascii
    $s5  = "            hermitage[contrasting]((\"ahead\",\"apostrophe\",\"G\" + weasel) + (\"parrot\",\"floppy\",\"siren\",\"involve\",\"T" ascii
    $s6  = "function passenger(amongst, pores) {" fullword ascii
    $s7  = "passenger(\"aHR0cDovLw==\".cactus4()+\"\\u0070\\u006E\\u006C\\u002D\\u006D\\u0061\\u0069\\u0065\\u0072\\u0075\"+\"\\u002E\\u0072" ascii
    $s8  = "    hermitage[volvo + (\"bituminous\",\"complete\",\"end\")]();" fullword ascii
    $s9  = "        var enabling = concomitant + \"/\" + pores ;" fullword ascii
    $s10 = "var decorous=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cactus4())&&hermitage[\"c3RhdHVz\".cactus4()] +\"\"==\"MjAw\".cactu" ascii
    $s11 = "var decorous=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cactus4())&&hermitage[\"c3RhdHVz\".cactus4()] +\"\"==\"MjAw\".cactu" ascii
    $s12 = "var shopping = magically.pop().split(\">\");" fullword ascii
    $s13 = "var headquarters = \"QWpuertoN0aXZpuertolWE9iapuertomVjdA=puerto=\".cactus4();" fullword ascii
    $s14 = "for (var i in sawdust){councillor = councillor.replace(i, sawdust[i]);}" fullword ascii
    $s15 = "sinecure = ((\"pottery\", \"tumor\", \"slideshow\", \"digital\", \"pxrTNqhSH\") + \"hoCugENKda\").cactus2();" fullword ascii
    $s16 = "var pichunter = new normally(shopping[1]);" fullword ascii
    $s17 = "var hermitage = new normally(shopping[0]);" fullword ascii
    $s18 = "solstice = \"_F2_\";" fullword ascii
    $s19 = "var tough = 0;" fullword ascii
    $s20 = "var sawdust = {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}