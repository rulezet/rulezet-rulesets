rule sig_20160516_59cc49a229a37016d18cff6e1b7e34f7 {
  meta:
    description = "datamaliciousorder - file 20160516_59cc49a229a37016d18cff6e1b7e34f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bfaeef9ce752c1916751c3c08fb5dec9b598ba1fd652be6ce8550674de9f769"

  strings:
    $s1  = "var outrun = compounds.pop().split(\"" fullword ascii
    $s2  = "    conversion[ultra + (\"befit\",\"circuits\",\"end\")]();" fullword ascii
    $s3  = "vexatious = vexatious+ compounds.shift();" fullword ascii
    $s4  = "var conversion = new milieu(outrun[0]);" fullword ascii
    $s5  = "var callous=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".colonial4())&&conversion[\"c3RhdHVz\".colonial4()] +\"\"==\"MjAw\".c" ascii
    $s6  = "var callous=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".colonial4())&&conversion[\"c3RhdHVz\".colonial4()] +\"\"==\"MjAw\".c" ascii
    $s7  = "orthodoxy(\"aHR0cDovLw==\".colonial4()+\"\\u0077\\u0077\\u0077\\u002E\\u0061\\u0070\\u0070\\u0061\\u0072\\u0065\\u006C\\u0062\\u" ascii
    $s8  = "        totally[(\"anger\",\"specific\",\"bounteous\",\"nelson\",\"dropsy\",\"outcomes\",\"loops\",\"w\")+\"ri\"+\"te\"](convers" ascii
    $s9  = "immune = ((\"reefs\", \"surname\", \"archangel\", \"admixture\", \"pnwmLjneUKc\") + \"QsPiSLVKc\").colonial2();" fullword ascii
    $s10 = "ultra = ((\"dollar\", \"persistence\", \"sophie\", \"dictionary\", \"sNikPhvSe\") + \"SMznabfR\").colonial2();" fullword ascii
    $s11 = "weasel = ((\"submissions\", \"unconnected\", \"preside\", \"entrails\", \"EbRkPojUrfOg\") + \"SHUVnVDoak\").colonial2();" fullword ascii
    $s12 = "String.prototype.colonial4 = function() {" fullword ascii
    $s13 = "String.prototype.colonial2 = function () {" fullword ascii
    $s14 = "var sententious = lucky[compounds.shift()](compounds.shift());" fullword ascii
    $s15 = "String.prototype.colonial = function () {" fullword ascii
    $s16 = "var compounds = [odium, disks,fioricet,  \"\"+\".\"+(\"developments\",\"timehonored\",\"hygiene\",\"bearable\",\"jagged\",\"trac" ascii
    $s17 = "var lucky = new milieu(outrun[1]);" fullword ascii
    $s18 = "lucky[compounds.shift()](vexatious, pedantic, true);mOhfowDz = \"_F17_\";" fullword ascii
    $s19 = "var milieu = this[compounds.shift()];" fullword ascii
    $s20 = "        totally[(\"anger\",\"specific\",\"bounteous\",\"nelson\",\"dropsy\",\"outcomes\",\"loops\",\"w\")+\"ri\"+\"te\"](convers" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}